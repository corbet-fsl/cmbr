//! Target-owner and persistence boundaries, not GlobalRoot host authorization.
use super::*;

struct Unsupported;
impl CreationGuard for Unsupported {}

// This fixture checks the genuine current target issuer only. Production must
// additionally retain the independently authenticated GlobalRoot owner/writer.
struct TargetIssuer<'a> {
    policy: &'a SqlPolicy,
    invitation: &'a [u8],
    clock: common::Clock,
    releases: usize,
    expire_after_commit: bool,
}
impl CreationGuard for TargetIssuer<'_> {
    async fn check(&mut self, context: &CreationContext<'_>, observed: u64) -> Result<()> {
        let verified = cvch::role::verify(
            self.invitation,
            self.policy.key_ring().map_err(|_| Error::Policy)?,
            &cvch::role::Context {
                community: context.community(),
                member: context.member(),
                purpose: cvch::role::Purpose::BootstrapRoot,
                now: observed,
            },
        )
        .map_err(|_| Error::Policy)?;
        if verified.receipt() != context.receipt()
            || verified.binding() != context.binding()
            || verified.valid_until() != context.expires_at()
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
    fn release(&mut self, context: &CreationContext<'_>, observed: u64) -> Result<()> {
        self.releases += 1;
        if self.expire_after_commit && self.releases == 2 {
            self.clock.set(context.expires_at() as i64);
        }
        if observed >= context.expires_at() {
            return Err(Error::Transition);
        }
        Ok(())
    }
}

fn verified(fixture: &Fixture, invitation: &[u8]) -> cvch::role::Verified {
    cvch::role::verify(
        invitation,
        fixture.policy.key_ring().unwrap(),
        &cvch::role::Context {
            community: COMMUNITY,
            member: common::SUBJECT.as_bytes(),
            purpose: cvch::role::Purpose::BootstrapRoot,
            now: common::now() as u64,
        },
    )
    .unwrap()
}
fn request<'a>(fixture: &'a Fixture, invitation: &'a cvch::role::Verified) -> CreationRequest<'a> {
    CreationRequest {
        invitation,
        authentication: &fixture.authentication,
        session: &fixture.session,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_creation_guard_rolls_back_the_actual_staged_phase() {
    let fixture = Fixture::new().await;
    let bytes = fixture.first_invitation();
    let invitation = verified(&fixture, &bytes);
    assert_eq!(
        fixture
            .owner
            .initialize_community_creation_checked(request(&fixture, &invitation), &mut Unsupported)
            .await,
        Err(Error::Unavailable)
    );
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Uninitialized
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_original_target_key_cannot_install_creating() {
    let fixture = Fixture::new().await;
    let bytes = fixture.first_invitation();
    let invitation = verified(&fixture, &bytes);
    let keys = fixture.owner.passkeys.clone();
    let user = fixture.authentication.member();
    let credential = fixture.authentication.credential_id().clone();
    super::super::blocking(move || keys.revoke(user, &credential))
        .await
        .unwrap();
    let mut producer = TargetIssuer {
        policy: &fixture.policy,
        invitation: &bytes,
        clock: fixture.clock.clone(),
        releases: 0,
        expire_after_commit: false,
    };
    assert_eq!(
        fixture
            .owner
            .initialize_community_creation_checked(request(&fixture, &invitation), &mut producer)
            .await,
        Err(Error::Passkey)
    );
    assert_eq!(producer.releases, 0);
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Uninitialized
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn target_signed_creation_retries_preserve_the_exact_original_tuple() {
    let fixture = Fixture::new().await;
    let bytes = fixture.first_invitation();
    let invitation = verified(&fixture, &bytes);
    let mut producer = TargetIssuer {
        policy: &fixture.policy,
        invitation: &bytes,
        clock: fixture.clock.clone(),
        releases: 0,
        expire_after_commit: false,
    };
    for _ in 0..2 {
        assert_eq!(
            fixture
                .owner
                .initialize_community_creation_checked(
                    request(&fixture, &invitation),
                    &mut producer
                )
                .await
                .unwrap(),
            CommunityPhase::Creating
        );
    }
    let tx = fixture.db.community(COMMUNITY).unwrap().tx().await.unwrap();
    let (tx, retained) = fixture.owner.creation().read(tx).await.unwrap();
    assert!(matches!(retained, Some(Phase::Creating(pending))
        if pending.receipt() == invitation.receipt()
        && pending.binding() == invitation.binding()
        && pending.expires() == invitation.valid_until()));
    tx.rollback().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_postcommit_creation_is_uncertain_and_retains_the_winner() {
    let fixture = Fixture::new().await;
    let bytes = fixture.first_invitation();
    let invitation = verified(&fixture, &bytes);
    let mut producer = TargetIssuer {
        policy: &fixture.policy,
        invitation: &bytes,
        clock: fixture.clock.clone(),
        releases: 0,
        expire_after_commit: true,
    };
    assert_eq!(
        fixture
            .owner
            .initialize_community_creation_checked(request(&fixture, &invitation), &mut producer)
            .await,
        Err(Error::Unavailable)
    );
    assert_eq!(producer.releases, 2);
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Creating
    );
}

struct Waiting {
    entered: Arc<tokio::sync::Notify>,
}
impl CreationGuard for Waiting {
    async fn check(&mut self, _: &CreationContext<'_>, _: u64) -> Result<()> {
        self.entered.notify_one();
        std::future::pending().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_inside_final_producer_read_rolls_back_the_real_staged_phase() {
    let fixture = Fixture::new().await;
    let bytes = fixture.first_invitation();
    let invitation = verified(&fixture, &bytes);
    let entered = Arc::new(tokio::sync::Notify::new());
    let mut producer = Waiting {
        entered: entered.clone(),
    };
    let mut operation = Box::pin(
        fixture
            .owner
            .initialize_community_creation_checked(request(&fixture, &invitation), &mut producer),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut operation => panic!("unexpected completed creation: {result:?}"),
            _ = entered.notified() => {}
        }
    })
    .await
    .unwrap();
    drop(operation);
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Uninitialized
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independently_opened_same_file_writer_refuses_before_target_creation_staging() {
    let fixture = Fixture::new().await;
    let bytes = fixture.first_invitation();
    let invitation = verified(&fixture, &bytes);
    let mut config = crlt::Config::new(
        format!(
            "file://{}",
            fixture._directory.path().join("creation.db").display()
        ),
        "",
    );
    config.max_connections = 2;
    config.busy_timeout = Duration::from_millis(100);
    let other = crlt::Db::open(config).await.unwrap();
    other.migrate(&migrations()).await.unwrap();
    // Lower database contention only: this scope is not GlobalRoot authority.
    let writer = other.community("root").unwrap().tx().await.unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let mut producer = Waiting {
        entered: entered.clone(),
    };
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(5),
            fixture.owner.initialize_community_creation_checked(
                request(&fixture, &invitation),
                &mut producer,
            )
        )
        .await
        .unwrap(),
        Err(Error::Unavailable)
    );
    // The final producer callback never ran; the target could not obtain its
    // original Immediate writer while the independent same-file owner held it.
    assert!(
        tokio::time::timeout(Duration::from_millis(1), entered.notified())
            .await
            .is_err()
    );
    writer.rollback().await.unwrap();
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Uninitialized
    );
}
