use std::collections::HashSet;

use futures::future::join_all;
use tokio_util::sync::CancellationToken;

use crate::domain::{
    FieldValue, Filter, FilterOperator, InfobaseRecord, QueryEngine, QueryOutcome, QuerySpec,
    RecordKind, SqlMask, TargetError, TargetErrorKind,
};

use super::{
    AppError, AppServices, ClusterSelector, ConfiguredTarget, LiveCluster, RacOptions,
    finish_target_results, normalize_infobase, resolved_query_spec, select_configured_targets,
};

#[derive(Clone, Debug)]
pub struct InfobaseSearchRequest {
    pub name: SqlMask,
    pub clusters: ClusterSelector,
    pub query: Option<QuerySpec>,
    pub rac_options: RacOptions,
}

impl InfobaseSearchRequest {
    pub fn new(name: &str) -> Result<Self, AppError> {
        Ok(Self {
            name: SqlMask::parse(name).map_err(AppError::from_domain)?,
            clusters: ClusterSelector::all(),
            query: None,
            rac_options: RacOptions::default(),
        })
    }
}

impl AppServices {
    pub async fn search_infobases(
        &self,
        request: &InfobaseSearchRequest,
        cancellation: &CancellationToken,
    ) -> Result<QueryOutcome<InfobaseRecord>, AppError> {
        let mut query = resolved_query_spec(RecordKind::Infobase, &request.query, &self.fields)?;
        query
            .push_filter(
                Filter::from_value(
                    RecordKind::Infobase,
                    "infobase",
                    FilterOperator::Like,
                    FieldValue::Str(request.name.source().to_owned()),
                    &self.fields,
                )
                .map_err(AppError::from_domain)?,
            )
            .map_err(AppError::from_domain)?;

        let snapshot = self.load_config_snapshot(cancellation).await?;
        let targets = select_configured_targets(&snapshot, &request.clusters)?;
        let results =
            join_all(targets.iter().map(|target| {
                self.infobases_for_target(target, &request.rac_options, cancellation)
            }))
            .await;

        let mut data = Vec::new();
        let mut errors = Vec::new();
        let mut successful_targets = 0_usize;
        for result in results {
            match result {
                Ok(mut records) => {
                    successful_targets += 1;
                    data.append(&mut records);
                }
                Err(error) => errors.push(error),
            }
        }
        self.update_diagnostics(&targets, &errors).await;
        let (data, errors, successful_targets) =
            finish_target_results(cancellation, data, errors, successful_targets)?;
        QueryEngine::new()
            .execute(data, errors, successful_targets, &query)
            .map_err(AppError::from_domain)
    }

    pub async fn infobase_search(
        &self,
        request: &InfobaseSearchRequest,
        cancellation: &CancellationToken,
    ) -> Result<QueryOutcome<InfobaseRecord>, AppError> {
        self.search_infobases(request, cancellation).await
    }

    pub(crate) async fn infobases_for_target(
        &self,
        target: &ConfiguredTarget,
        options: &RacOptions,
        cancellation: &CancellationToken,
    ) -> Result<Vec<InfobaseRecord>, TargetError> {
        let live = self.live_cluster(target, options, cancellation).await?;
        self.infobases_for_live(target, &live, cancellation).await
    }

    pub(crate) async fn infobases_for_live(
        &self,
        target: &ConfiguredTarget,
        live: &LiveCluster,
        cancellation: &CancellationToken,
    ) -> Result<Vec<InfobaseRecord>, TargetError> {
        let records = self
            .rac
            .infobase_list(
                target.target.ras.as_str(),
                live.cluster.uuid.into_uuid(),
                &target.cluster_credentials,
                &live.search_policy,
                cancellation,
            )
            .await
            .map_err(|error| {
                super::error::target_error_from_rac(
                    target.target.alias.clone(),
                    target.target.ras.clone(),
                    error,
                )
            })?;
        let mut seen = HashSet::with_capacity(records.len());
        let mut normalized = Vec::with_capacity(records.len());
        for record in &records {
            let item = normalize_infobase(record, live.source.clone(), &live.cluster).map_err(
                |error| {
                    TargetError::new(
                        target.target.alias.clone(),
                        target.target.ras.clone(),
                        TargetErrorKind::InvalidResponse,
                        error.to_string(),
                    )
                },
            )?;
            if !seen.insert(item.infobase_uuid) {
                return Err(TargetError::new(
                    target.target.alias.clone(),
                    target.target.ras.clone(),
                    TargetErrorKind::InvalidResponse,
                    format!(
                        "RAC вернул повторяющийся UUID информационной базы {}",
                        item.infobase_uuid
                    ),
                ));
            }
            normalized.push(item);
        }
        Ok(normalized)
    }
}
