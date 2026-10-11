//! Genuine separate first-Root setup for ordinary membership-owner tests.
//!
//! The original development gate is an external provider fixture; this does
//! not qualify a complete Global passport or creation host journey.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

const ROOT_USER: Uuid = Uuid::from_u128(u128::MAX);
const ROOT_HANDLE: &str = "separate_fixture_root";
fn root_subject() -> String {
    "fe".repeat(48)
}

/// Exact original fixture session, never inferred from a member's role.
pub struct Session {
    authentication: ckyh::Authentication,
    until: u64,
    live: AtomicBool,
}
impl Session {
    pub fn new(authentication: &ckyh::Authentication, until: u64) -> Self {
        Self {
            authentication: authentication.clone(),
            until,
            live: AtomicBool::new(true),
        }
    }
}
impl cmbr::RoleSession for Session {
    fn valid_until(&self) -> u64 {
        self.until
    }
    fn check(&self, authentication: &ckyh::Authentication, observed: u64) -> cmbr::Result<()> {
        if !self.live.load(Ordering::SeqCst)
            || observed >= self.until
            || authentication.community() != self.authentication.community()
            || authentication.member() != self.authentication.member()
            || authentication.credential_id() != self.authentication.credential_id()
        {
            return Err(cmbr::Error::Identity);
        }
        Ok(())
    }
}

pub fn admission_request<'a>(
    authentication: &'a ckyh::Authentication,
    policy: &'a Policy,
    snapshot: &'a cplc::VerifiedSnapshot,
    gates: &'a cgts::CheckedGates,
    checked_at: u64,
    lease: crgs::YearMonth,
    session: &'a Session,
) -> cmbr::AdmissionRequest<'a, crbk::MemoryStore, cplc::MemoryStore, cplc::csgn::MemoryStore> {
    cmbr::AdmissionRequest {
        authentication,
        policy,
        snapshot,
        gates,
        checked_at,
        lease,
        session,
    }
}

pub async fn ensure_active<C: clbs::Clock + 'static>(
    owner: &cmbr::Membership<cmbr::LibsqlStorage, Verify, C>,
) -> cmbr::Result<()> {
    match owner.community_phase().await? {
        cmbr::CommunityPhase::Active => return Ok(()),
        cmbr::CommunityPhase::Uninitialized => {}
        cmbr::CommunityPhase::Creating | cmbr::CommunityPhase::LegacyActive => {
            return Err(cmbr::Error::Transition);
        }
    }
    let subject = root_subject();
    let mut token = register(owner, ROOT_USER, &subject).await;
    let authentication = login(owner, &mut token, ROOT_USER).await.authentication;
    owner
        .reserve_handle(&authentication, ROOT_HANDLE, &[])
        .await?;
    let mut policy = verified_policy(&policy(owner.community()), now()).await;
    let snapshot = policy.verified_settings(now() as u64).await.unwrap();
    let gates = checked(
        &snapshot,
        &subject,
        &[test_gate(owner.community(), &subject)],
        now(),
    )
    .await;
    let binding = cvch::member_binding(&cvch::receipt_id("fixture-first-root"), subject.as_bytes());
    let fields = cvch::role::Invitation {
        id: "fixture-first-root",
        community: owner.community(),
        member_binding: &binding,
        purpose: cvch::role::Purpose::BootstrapRoot,
        issued_at: now() as u64,
        valid_until: now() as u64 + 3600,
    };
    // The ACTUAL persistent target Policy issues the original recipient-bound
    // entitlement. No admitted row, role or phase is fabricated.
    let invitation = policy.issue_role_invitation(&fields).await.unwrap();
    let verified = cvch::role::verify(
        &invitation,
        policy.key_ring().unwrap(),
        &cvch::role::Context {
            community: owner.community(),
            member: subject.as_bytes(),
            purpose: cvch::role::Purpose::BootstrapRoot,
            now: now() as u64,
        },
    )
    .unwrap();
    assert_eq!(
        owner
            .initialize_community_creation(&verified, subject.as_bytes())
            .await?,
        cmbr::CommunityPhase::Creating
    );
    let session = Session::new(&authentication, fields.valid_until);
    let admitted = owner
        .admit_first_root(
            admission_request(
                &authentication,
                &policy,
                &snapshot,
                &gates,
                now() as u64,
                lease(),
                &session,
            ),
            &invitation,
        )
        .await?;
    assert_eq!(admitted.state(), cnrl::State::Admitted);
    let root = owner.member(&authentication).await?.unwrap();
    assert_eq!(root.role, crgs::Role::Root);
    assert_eq!(root.id.as_bytes(), subject.as_bytes());
    assert_eq!(owner.community_phase().await?, cmbr::CommunityPhase::Active);
    Ok(())
}
