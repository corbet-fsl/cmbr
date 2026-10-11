use super::*;
use crate::storage::role_redemptions::{Redemption, RoleRedemptions};

const USER: ckyh::Uuid = ckyh::Uuid::from_u128(2);
const HANDLE: &str = "founder_user";
pub(super) const INVITATION_ID: &str = "original-founder-admin";

pub(super) struct Founder {
    pub base: Fixture,
    pub subject: String,
    pub authentication: Authentication,
    pub gates: cgts::CheckedGates,
    pub session: Session,
}

impl Founder {
    pub async fn new(active: bool) -> Self {
        let base = Fixture::new().await;
        let original = base.first_invitation();
        base.initialize(&original).await;
        if active {
            base.owner
                .admit_first_root(base.request(), &original)
                .await
                .unwrap();
        }
        // Separate actual SDK registration, subject and handle: the original
        // first Root is never repurposed into the joining FounderAdmin.
        let subject = "a1".repeat(48);
        let mut token = common::register(&base.owner, USER, &subject).await;
        let authentication = common::login(&base.owner, &mut token, USER)
            .await
            .authentication;
        base.owner
            .reserve_handle(&authentication, HANDLE, &[])
            .await
            .unwrap();
        let gates = common::checked(
            &base.snapshot,
            &subject,
            &[common::test_gate(COMMUNITY, &subject)],
            common::now(),
        )
        .await;
        let session = Session::new(&authentication);
        Self {
            base,
            subject,
            authentication,
            gates,
            session,
        }
    }

    pub fn member(&self) -> crgs::MemberId {
        crgs::MemberId::new(self.subject.as_bytes()).unwrap()
    }

    pub fn request(
        &self,
    ) -> AdmissionRequest<'_, crbk::LibsqlStore, cplc::LibsqlStore, cplc::csgn::LibsqlStore> {
        AdmissionRequest {
            authentication: &self.authentication,
            policy: &self.base.policy,
            snapshot: &self.base.snapshot,
            gates: &self.gates,
            checked_at: common::now() as u64,
            lease: common::lease(),
            session: &self.session,
        }
    }

    pub async fn invitation(&mut self, id: &str, member: &[u8], until: u64) -> Vec<u8> {
        let binding = cvch::member_binding(&cvch::receipt_id(id), member);
        self.base
            .policy
            .issue_role_invitation(&cvch::role::Invitation {
                id,
                community: COMMUNITY,
                member_binding: &binding,
                purpose: cvch::role::Purpose::FounderAdmin,
                issued_at: cplc::day(common::now() as u64),
                valid_until: until,
            })
            .await
            .unwrap()
    }

    pub async fn original(&mut self) -> Vec<u8> {
        let subject = self.subject.clone();
        self.invitation(
            INVITATION_ID,
            subject.as_bytes(),
            common::now() as u64 + 600,
        )
        .await
    }

    pub async fn row(&self) -> Record {
        // Pure lifecycle observation; enrolment_state would synchronize legal
        // restrictions and mutate the evidence being checked here.
        self.base
            .owner
            .enrol
            .view(USER, self.base.owner.now().unwrap())
            .await
            .unwrap()
    }

    pub async fn effect(&self) -> Option<Redemption> {
        let tx = self
            .base
            .db
            .community(COMMUNITY)
            .unwrap()
            .tx()
            .await
            .unwrap();
        let (tx, effect) = RoleRedemptions::new(self.base.owner.authority_scope.clone())
            .read(tx, &cvch::receipt_id(INVITATION_ID))
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        effect
    }

    pub async fn claim_present(&self) -> bool {
        let rows = self
            .base
            .db
            .community(COMMUNITY)
            .unwrap()
            .query(
                "SELECT marker FROM cgts_spent WHERE domain = ?1 AND marker = ?2",
                crlt::params!["cvch", cvch::receipt_id(INVITATION_ID).as_bytes().to_vec()],
            )
            .await
            .unwrap();
        assert!(rows.len() <= 1);
        !rows.is_empty()
    }

    pub async fn assert_unadmitted(&self, original: &Record) {
        assert_eq!(self.row().await, *original);
        assert_eq!(self.row().await.state(), State::HandleReserved);
        assert!(
            self.base
                .owner
                .register
                .member(&self.member())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            self.base
                .owner
                .storage
                .probation(&self.subject)
                .await
                .unwrap()
                .is_none()
        );
        assert!(self.effect().await.is_none());
        assert!(!self.claim_present().await);
    }

    pub async fn assert_admitted(&self) -> Record {
        let row = self.row().await;
        assert_eq!(row.state(), State::Admitted);
        let member = self
            .base
            .owner
            .register
            .member(&self.member())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.role, crgs::Role::Admin);
        assert_eq!(member.lease_end, common::lease());
        assert!(member.handle.is_some());
        let settings =
            crbk::MembershipSettings::from_snapshot(self.base.snapshot.settings()).unwrap();
        assert_eq!(
            self.base
                .owner
                .storage
                .probation(&self.subject)
                .await
                .unwrap(),
            Some(Some(
                cplc::day(common::now() as u64) + u64::from(settings.probation_days) * cplc::DAY
            ))
        );
        let effect = self.effect().await.unwrap();
        assert_eq!(effect.receipt(), cvch::receipt_id(INVITATION_ID));
        assert_eq!(
            effect.binding(),
            cvch::member_binding(effect.receipt(), self.subject.as_bytes())
        );
        assert_eq!(effect.expires(), common::now() as u64 + 600);
        assert_eq!(effect.member(), &self.member());
        assert_eq!(effect.lease(), common::lease());
        assert_eq!(effect.admitted_revision(), row.revision());
        assert!(self.claim_present().await);
        assert_eq!(
            self.base.owner.community_phase().await.unwrap(),
            CommunityPhase::Active
        );
        assert_eq!(
            self.base
                .owner
                .register
                .member(&root_id())
                .await
                .unwrap()
                .unwrap()
                .role,
            crgs::Role::Root
        );
        row
    }
}
