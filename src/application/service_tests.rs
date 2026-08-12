use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use indexmap::IndexMap;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::domain::{
    ClusterAlias, ClusterSource, ClusterUuid, ConnectionKillPlan, ConnectionRecord, ConnectionUuid,
    InfobaseUuid, ProcessUuid, SessionKillPlan, SessionRecord, SessionUuid, SnapshotId,
};
use crate::infrastructure::config;
use crate::infrastructure::rac::{
    RacAuthMode, RacCandidate, RacCredentials, RacError, RacErrorKind, RacRecord, SearchPolicy,
};
use crate::infrastructure::telemetry::AuditEvent;

use super::*;

#[derive(Clone)]
struct FakeConfig {
    snapshot: RawConfigSnapshot,
    loads: Arc<AtomicUsize>,
}

#[async_trait]
impl ConfigRepository for FakeConfig {
    async fn load(&self) -> Result<RawConfigSnapshot, PortError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        Ok(self.snapshot.clone())
    }

    async fn add_cluster(
        &self,
        _alias: String,
        _cluster: config::ClusterConfig,
    ) -> Result<RawConfigSnapshot, PortError> {
        Err(PortError::new(
            PortErrorKind::Internal,
            "not_implemented",
            "Тестовый порт не поддерживает запись",
        ))
    }

    async fn remove_cluster(&self, _alias: String) -> Result<RawConfigSnapshot, PortError> {
        Err(PortError::new(
            PortErrorKind::Internal,
            "not_implemented",
            "Тестовый порт не поддерживает запись",
        ))
    }

    async fn add_override(
        &self,
        _cluster_alias: String,
        _entry: config::InfobaseAuthOverride,
    ) -> Result<RawConfigSnapshot, PortError> {
        Err(PortError::new(
            PortErrorKind::Internal,
            "not_implemented",
            "Тестовый порт не поддерживает запись",
        ))
    }

    async fn remove_override(
        &self,
        _cluster_alias: String,
        _selector: config::OverrideSelector,
    ) -> Result<RawConfigSnapshot, PortError> {
        Err(PortError::new(
            PortErrorKind::Internal,
            "not_implemented",
            "Тестовый порт не поддерживает запись",
        ))
    }
}

#[derive(Default)]
struct FakeRacState {
    clusters: HashMap<String, Uuid>,
    unavailable: HashSet<String>,
    failed_sessions: HashSet<Uuid>,
    terminated: Vec<Uuid>,
    disconnected: Vec<(Uuid, Uuid, RacAuthMode, Option<String>)>,
}

#[derive(Clone, Default)]
struct FakeRac {
    state: Arc<Mutex<FakeRacState>>,
}

impl FakeRac {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeRacState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait]
impl RacPort for FakeRac {
    async fn cluster_list(
        &self,
        ras_address: &str,
        _search_policy: &SearchPolicy,
        _cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let state = self.state();
        if state.unavailable.contains(ras_address) {
            return Err(RacError::new(RacErrorKind::Timeout));
        }
        let Some(uuid) = state.clusters.get(ras_address).copied() else {
            return Err(RacError::new(RacErrorKind::Unknown));
        };
        Ok(vec![cluster_record(uuid, ras_address)])
    }

    async fn cluster_info(
        &self,
        _ras_address: &str,
        _cluster_id: Uuid,
        _cluster_credentials: &RacCredentials,
        _search_policy: &SearchPolicy,
        _cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        Ok(Vec::new())
    }

    async fn infobase_list(
        &self,
        _ras_address: &str,
        _cluster_id: Uuid,
        _cluster_credentials: &RacCredentials,
        _search_policy: &SearchPolicy,
        _cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let mut record = RacRecord::new();
        record.insert("infobase", Uuid::from_u128(100).to_string());
        record.insert("name", "Accounting");
        Ok(vec![record])
    }

    async fn session_list(
        &self,
        _ras_address: &str,
        _cluster_id: Uuid,
        _cluster_credentials: &RacCredentials,
        _search_policy: &SearchPolicy,
        _cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let mut record = RacRecord::new();
        record.insert("session", Uuid::from_u128(200).to_string());
        record.insert("session-id", "7");
        record.insert("infobase", Uuid::from_u128(100).to_string());
        record.insert("user-name", "DOMAIN\\user");
        record.insert("host", "PC-01");
        Ok(vec![record])
    }

    async fn session_terminate(
        &self,
        _ras_address: &str,
        _cluster_id: Uuid,
        session_id: Uuid,
        _message: Option<&str>,
        _cluster_credentials: &RacCredentials,
        _search_policy: &SearchPolicy,
        _cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let mut state = self.state();
        state.terminated.push(session_id);
        if state.failed_sessions.contains(&session_id) {
            Err(RacError::new(RacErrorKind::Auth))
        } else {
            Ok(Vec::new())
        }
    }

    async fn connection_list(
        &self,
        _ras_address: &str,
        _cluster_id: Uuid,
        _cluster_credentials: &RacCredentials,
        _search_policy: &SearchPolicy,
        _cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        Ok(Vec::new())
    }

    async fn connection_disconnect(
        &self,
        _ras_address: &str,
        _cluster_id: Uuid,
        process_id: Uuid,
        connection_id: Uuid,
        _cluster_credentials: &RacCredentials,
        infobase_credentials: &RacCredentials,
        _search_policy: &SearchPolicy,
        _cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        self.state().disconnected.push((
            process_id,
            connection_id,
            infobase_credentials.mode(),
            infobase_credentials.username().map(str::to_owned),
        ));
        Ok(Vec::new())
    }

    async fn chosen_candidate(&self, _ras_address: &str) -> Option<RacCandidate> {
        None
    }
}

#[derive(Clone, Default)]
struct FakeAudit {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

#[async_trait]
impl AuditPort for FakeAudit {
    async fn record(&self, event: AuditEvent) -> Result<(), PortError> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct FakeIdentity;

#[async_trait]
impl IdentityPort for FakeIdentity {
    async fn current_identity(&self) -> Result<String, PortError> {
        Ok(r"DOMAIN\operator".to_owned())
    }

    async fn verify_expected(&self, _expected: String) -> Result<String, PortError> {
        Ok(r"DOMAIN\operator".to_owned())
    }
}

fn cluster_record(uuid: Uuid, ras_address: &str) -> RacRecord {
    let mut record = RacRecord::new();
    record.insert("cluster", uuid.to_string());
    record.insert("name", format!("Cluster {uuid}"));
    record.insert(
        "host",
        ras_address.split(':').next().unwrap_or("cluster.local"),
    );
    record.insert("port", "1541");
    record
}

fn raw_snapshot(entries: &[(&str, &str, Uuid)], infobase_password: bool) -> RawConfigSnapshot {
    let mut clusters = IndexMap::new();
    for (alias, host, uuid) in entries {
        clusters.insert(
            (*alias).to_owned(),
            config::ClusterConfig {
                ras: config::RasConfig {
                    host: (*host).to_owned(),
                    port: 1545,
                },
                discovered_cluster: config::DiscoveredCluster {
                    uuid: *uuid,
                    name: format!("Cluster {alias}"),
                    host: (*host).to_owned(),
                    port: 1541,
                },
                rac: config::RacConfig::default(),
                cluster_auth: config::AuthConfig::none(),
                infobase_auth: config::InfobaseAuthConfig {
                    default: if infobase_password {
                        config::AuthConfig::password("ib-admin", config::Password::new("secret"))
                    } else {
                        config::AuthConfig::none()
                    },
                    overrides: Vec::new(),
                },
            },
        );
    }
    RawConfigSnapshot {
        path: "config.yaml".into(),
        config: config::Config {
            schema_version: config::CONFIG_SCHEMA_VERSION,
            settings: config::Settings::default(),
            clusters,
        },
    }
}

fn services(
    snapshot: RawConfigSnapshot,
    rac: FakeRac,
    audit: FakeAudit,
    loads: Arc<AtomicUsize>,
) -> AppServices {
    AppServices::new(FakeConfig { snapshot, loads }, rac, audit, FakeIdentity)
}

fn source(alias: &str, cluster_uuid: Uuid) -> ClusterSource {
    ClusterSource::new(
        ClusterAlias::new(alias).unwrap_or_else(|error| panic!("{error}")),
        ClusterUuid::new(cluster_uuid),
        "Cluster",
        "good.local:1545"
            .parse()
            .unwrap_or_else(|error| panic!("{error}")),
    )
}

#[tokio::test]
async fn session_fanout_returns_partial_data_and_joined_infobase() {
    let good_uuid = Uuid::from_u128(1);
    let bad_uuid = Uuid::from_u128(2);
    let snapshot = raw_snapshot(
        &[
            ("z-good", "good.local", good_uuid),
            ("a-bad", "bad.local", bad_uuid),
        ],
        false,
    );
    let rac = FakeRac::default();
    {
        let mut state = rac.state();
        state
            .clusters
            .insert("good.local:1545".to_owned(), good_uuid);
        state.clusters.insert("bad.local:1545".to_owned(), bad_uuid);
        state.unavailable.insert("bad.local:1545".to_owned());
    }
    let app = services(
        snapshot,
        rac,
        FakeAudit::default(),
        Arc::new(AtomicUsize::new(0)),
    );

    let outcome = app
        .list_sessions(&SessionListRequest::default(), &CancellationToken::new())
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(outcome.data.len(), 1);
    assert_eq!(outcome.data[0].infobase.as_deref(), Some("Accounting"));
    assert_eq!(outcome.errors.len(), 1);
    assert!(outcome.meta.partial);
    assert_eq!(outcome.app_exit_code(), AppExitCode::PartialSuccess);
}

#[tokio::test]
async fn destructive_guard_runs_before_config_or_rac_io() {
    let loads = Arc::new(AtomicUsize::new(0));
    let app = services(
        raw_snapshot(&[], false),
        FakeRac::default(),
        FakeAudit::default(),
        Arc::clone(&loads),
    );

    let error = app
        .prepare_session_kill(&SessionKillRequest::default(), &CancellationToken::new())
        .await
        .err()
        .unwrap_or_else(|| panic!("selector guard must reject the request"));

    assert_eq!(error.code(), "selector_required");
    assert_eq!(loads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cluster_remove_never_treats_underscore_as_a_mask() {
    let snapshot = raw_snapshot(&[("prodX1", "good.local", Uuid::from_u128(1))], false);
    let app = services(
        snapshot,
        FakeRac::default(),
        FakeAudit::default(),
        Arc::new(AtomicUsize::new(0)),
    );

    let error = app
        .prepare_cluster_remove("prod_1", &CancellationToken::new())
        .await
        .err()
        .unwrap_or_else(|| panic!("remove must require an exact alias"));

    assert_eq!(error.code(), "no_objects");
}

#[tokio::test]
async fn credential_overrides_are_loaded_through_the_typed_snapshot() {
    let mut snapshot = raw_snapshot(&[("dev", "good.local", Uuid::from_u128(1))], false);
    let Some(cluster) = snapshot.config.clusters.get_mut("dev") else {
        panic!("test cluster must exist");
    };
    cluster
        .infobase_auth
        .overrides
        .push(config::InfobaseAuthOverride::none(
            "Accounting",
            Some(Uuid::from_u128(100)),
        ));
    let app = services(
        snapshot,
        FakeRac::default(),
        FakeAudit::default(),
        Arc::new(AtomicUsize::new(0)),
    );

    let overrides = app
        .credential_overrides("DEV", &CancellationToken::new())
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].infobase(), Some("Accounting"));
    assert_eq!(
        overrides[0].infobase_uuid(),
        Some(InfobaseUuid::new(Uuid::from_u128(100)))
    );
}

#[tokio::test]
async fn session_kill_continues_after_item_error_and_audits_every_item() {
    let cluster_uuid = Uuid::from_u128(1);
    let first_id = Uuid::from_u128(10);
    let second_id = Uuid::from_u128(11);
    let snapshot = raw_snapshot(&[("dev", "good.local", cluster_uuid)], false);
    let rac = FakeRac::default();
    {
        let mut state = rac.state();
        state
            .clusters
            .insert("good.local:1545".to_owned(), cluster_uuid);
        state.failed_sessions.insert(first_id);
    }
    let audit = FakeAudit::default();
    let app = services(
        snapshot,
        rac.clone(),
        audit.clone(),
        Arc::new(AtomicUsize::new(0)),
    );
    let records = [first_id, second_id]
        .into_iter()
        .map(|id| SessionRecord::new(source("dev", cluster_uuid), SessionUuid::new(id)))
        .collect::<Vec<_>>();
    let plan = SessionKillPlan::from_records(SnapshotId::random(), &records, None)
        .unwrap_or_else(|error| panic!("{error}"));

    let outcome = app
        .execute_session_kill(
            &plan,
            Approval::Forced,
            &RacOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(outcome.meta.failed, 1);
    assert_eq!(outcome.meta.succeeded, 1);
    assert_eq!(outcome.app_exit_code(), AppExitCode::PartialSuccess);
    assert_eq!(rac.state().terminated, vec![first_id, second_id]);
    assert_eq!(
        audit
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        2
    );
}

#[tokio::test]
async fn connection_kill_keeps_pair_and_uses_matching_infobase_credentials() {
    let cluster_uuid = Uuid::from_u128(1);
    let process_id = Uuid::from_u128(20);
    let connection_id = Uuid::from_u128(21);
    let snapshot = raw_snapshot(&[("dev", "good.local", cluster_uuid)], true);
    let rac = FakeRac::default();
    rac.state()
        .clusters
        .insert("good.local:1545".to_owned(), cluster_uuid);
    let app = services(
        snapshot,
        rac.clone(),
        FakeAudit::default(),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut record = ConnectionRecord::new(
        source("dev", cluster_uuid),
        ConnectionUuid::new(connection_id),
        ProcessUuid::new(process_id),
    );
    record.infobase = Some("Accounting".to_owned());
    record.infobase_uuid = Some(InfobaseUuid::new(Uuid::from_u128(100)));
    let plan = ConnectionKillPlan::from_records(SnapshotId::random(), &[record])
        .unwrap_or_else(|error| panic!("{error}"));

    let outcome = app
        .execute_connection_kill(
            &plan,
            Approval::Confirmed,
            &RacOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(outcome.meta.succeeded, 1);
    assert_eq!(
        rac.state().disconnected,
        vec![(
            process_id,
            connection_id,
            RacAuthMode::Password,
            Some("ib-admin".to_owned())
        )]
    );
}
