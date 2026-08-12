use onecadmin::application::{normalize_cluster, normalize_session};
use onecadmin::domain::{ClusterAlias, ClusterSource, ClusterUuid, RasEndpoint};
use onecadmin::infrastructure::rac::parse_rac_records;
use uuid::Uuid;

const CLUSTER_8_3_20: &str = include_str!("fixtures/rac/8.3.20/cluster-list.txt");
const SESSION_CURRENT: &str = include_str!("fixtures/rac/current/session-list.txt");

#[test]
fn parses_8_3_20_cluster_fixture() {
    let records = parse_rac_records(CLUSTER_8_3_20).expect("fixture must parse");
    assert_eq!(records.len(), 1);
    let cluster = normalize_cluster(&records[0]).expect("cluster must normalize");
    assert_eq!(cluster.host, "srv-1c.example.local");
    assert_eq!(cluster.port, 1541);
}

#[test]
fn current_fixture_preserves_rac_session_uuid_and_numeric_id_semantics() {
    let records = parse_rac_records(SESSION_CURRENT).expect("fixture must parse");
    let source = ClusterSource::new(
        ClusterAlias::new("dev").expect("alias must be valid"),
        ClusterUuid::new(Uuid::from_u128(1)),
        "Development",
        "ras.example.local:1545"
            .parse::<RasEndpoint>()
            .expect("endpoint must be valid"),
    );
    let session = normalize_session(&records[0], source).expect("session must normalize");

    assert_eq!(
        session.session.to_string(),
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    );
    assert_eq!(session.session_id, Some(42));
    assert_eq!(session.cpu_time_total, Some(1500));
}
