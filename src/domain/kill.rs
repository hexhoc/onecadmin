use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    ClusterAlias, ClusterUuid, ConnectionRecord, ConnectionUuid, DomainError, InfobaseUuid,
    ProcessUuid, RasEndpoint, SessionRecord, SessionUuid,
};

pub const DEFAULT_SESSION_KILL_MESSAGE: &str =
    "Сеанс принудительно завершен администратором через onecadmin";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotId(Uuid);

impl SnapshotId {
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionKillTarget {
    pub cluster: ClusterAlias,
    pub cluster_uuid: ClusterUuid,
    pub ras_address: RasEndpoint,
    pub infobase: Option<String>,
    pub infobase_uuid: Option<InfobaseUuid>,
    pub session_id: SessionUuid,
    pub session_number: Option<i64>,
}

impl From<&SessionRecord> for SessionKillTarget {
    fn from(record: &SessionRecord) -> Self {
        Self {
            cluster: record.source.cluster.clone(),
            cluster_uuid: record.source.cluster_uuid,
            ras_address: record.source.ras_address.clone(),
            infobase: record.infobase.clone(),
            infobase_uuid: record.infobase_uuid,
            session_id: record.session,
            session_number: record.session_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionKillPlan {
    snapshot_id: SnapshotId,
    targets: Box<[SessionKillTarget]>,
    message: String,
}

impl SessionKillPlan {
    pub fn new(
        snapshot_id: SnapshotId,
        targets: Vec<SessionKillTarget>,
        message: Option<String>,
    ) -> Result<Self, DomainError> {
        if targets.is_empty() {
            return Err(DomainError::EmptyKillPlan);
        }
        if targets.iter().any(|target| target.session_id.is_nil()) {
            return Err(DomainError::MissingKillIdentity { field: "session" });
        }
        let mut identities = HashSet::with_capacity(targets.len());
        if targets
            .iter()
            .any(|target| !identities.insert((target.cluster_uuid, target.session_id)))
        {
            return Err(DomainError::DuplicateKillTarget);
        }
        Ok(Self {
            snapshot_id,
            targets: targets.into_boxed_slice(),
            message: message.unwrap_or_else(|| DEFAULT_SESSION_KILL_MESSAGE.to_owned()),
        })
    }

    pub fn from_records(
        snapshot_id: SnapshotId,
        records: &[SessionRecord],
        message: Option<String>,
    ) -> Result<Self, DomainError> {
        Self::new(
            snapshot_id,
            records.iter().map(SessionKillTarget::from).collect(),
            message,
        )
    }

    #[must_use]
    pub const fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub fn targets(&self) -> &[SessionKillTarget] {
        &self.targets
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionKillTarget {
    pub cluster: ClusterAlias,
    pub cluster_uuid: ClusterUuid,
    pub ras_address: RasEndpoint,
    pub infobase: Option<String>,
    pub infobase_uuid: InfobaseUuid,
    pub process_id: ProcessUuid,
    pub connection_id: ConnectionUuid,
    pub connection_number: Option<i64>,
}

impl TryFrom<&ConnectionRecord> for ConnectionKillTarget {
    type Error = DomainError;

    fn try_from(record: &ConnectionRecord) -> Result<Self, Self::Error> {
        let infobase_uuid = record
            .infobase_uuid
            .ok_or(DomainError::MissingKillIdentity {
                field: "infobase_uuid",
            })?;
        if infobase_uuid.is_nil() {
            return Err(DomainError::MissingKillIdentity {
                field: "infobase_uuid",
            });
        }
        if record.process.is_nil() {
            return Err(DomainError::MissingKillIdentity { field: "process" });
        }
        if record.connection.is_nil() {
            return Err(DomainError::MissingKillIdentity {
                field: "connection",
            });
        }
        Ok(Self {
            cluster: record.source.cluster.clone(),
            cluster_uuid: record.source.cluster_uuid,
            ras_address: record.source.ras_address.clone(),
            infobase: record.infobase.clone(),
            infobase_uuid,
            process_id: record.process,
            connection_id: record.connection,
            connection_number: record.conn_id,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionKillPlan {
    snapshot_id: SnapshotId,
    targets: Box<[ConnectionKillTarget]>,
}

impl ConnectionKillPlan {
    pub fn new(
        snapshot_id: SnapshotId,
        targets: Vec<ConnectionKillTarget>,
    ) -> Result<Self, DomainError> {
        if targets.is_empty() {
            return Err(DomainError::EmptyKillPlan);
        }
        let mut identities = HashSet::with_capacity(targets.len());
        if targets.iter().any(|target| {
            !identities.insert((target.cluster_uuid, target.process_id, target.connection_id))
        }) {
            return Err(DomainError::DuplicateKillTarget);
        }
        Ok(Self {
            snapshot_id,
            targets: targets.into_boxed_slice(),
        })
    }

    pub fn from_records(
        snapshot_id: SnapshotId,
        records: &[ConnectionRecord],
    ) -> Result<Self, DomainError> {
        let targets = records
            .iter()
            .map(ConnectionKillTarget::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(snapshot_id, targets)
    }

    #[must_use]
    pub const fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub fn targets(&self) -> &[ConnectionKillTarget] {
        &self.targets
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ClusterSource, ConnectionRecord, ConnectionUuid, ProcessUuid, SessionRecord,
    };
    use super::*;

    fn source() -> super::super::ClusterSource {
        ClusterSource::new(
            ClusterAlias::new("dev").unwrap_or_else(|error| panic!("{error}")),
            ClusterUuid::new(Uuid::from_u128(1)),
            "cluster",
            "ras.local:1545"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        )
    }

    #[test]
    fn session_plan_uses_one_snapshot_and_default_message() {
        let records = vec![SessionRecord::new(
            source(),
            SessionUuid::new(Uuid::from_u128(2)),
        )];
        let snapshot = SnapshotId::new(Uuid::from_u128(100));
        let plan = SessionKillPlan::from_records(snapshot, &records, None)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(plan.snapshot_id(), snapshot);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.message(), DEFAULT_SESSION_KILL_MESSAGE);
    }

    #[test]
    fn duplicate_compound_identity_is_rejected() {
        let record = SessionRecord::new(source(), SessionUuid::new(Uuid::from_u128(2)));
        let result = SessionKillPlan::from_records(
            SnapshotId::new(Uuid::from_u128(100)),
            &[record.clone(), record],
            None,
        );

        assert_eq!(result, Err(DomainError::DuplicateKillTarget));
    }

    #[test]
    fn connection_plan_keeps_process_and_connection_from_same_record() {
        let mut record = ConnectionRecord::new(
            source(),
            ConnectionUuid::new(Uuid::from_u128(3)),
            ProcessUuid::new(Uuid::from_u128(4)),
        );
        record.infobase_uuid = Some(InfobaseUuid::new(Uuid::from_u128(5)));
        let plan =
            ConnectionKillPlan::from_records(SnapshotId::new(Uuid::from_u128(100)), &[record])
                .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(plan.targets()[0].connection_id.into_uuid().as_u128(), 3);
        assert_eq!(plan.targets()[0].process_id.into_uuid().as_u128(), 4);
    }

    #[test]
    fn connection_plan_requires_infobase_identity_for_credentials() {
        let record = ConnectionRecord::new(
            source(),
            ConnectionUuid::new(Uuid::from_u128(3)),
            ProcessUuid::new(Uuid::from_u128(4)),
        );

        assert!(matches!(
            ConnectionKillPlan::from_records(SnapshotId::new(Uuid::from_u128(100)), &[record]),
            Err(DomainError::MissingKillIdentity {
                field: "infobase_uuid"
            })
        ));
    }
}
