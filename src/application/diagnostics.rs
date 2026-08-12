use std::path::PathBuf;

use chrono::{DateTime, Utc};
use futures::future::join_all;

use crate::domain::{ClusterAlias, PlatformVersion, RasEndpoint, TargetError};

use super::{AppServices, ConfiguredTarget};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedRac {
    pub cluster: ClusterAlias,
    pub ras_address: RasEndpoint,
    pub path: PathBuf,
    pub version: PlatformVersion,
    pub origin: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiagnosticsSnapshot {
    pub selected_rac: Vec<SelectedRac>,
    pub target_errors: Vec<TargetError>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl AppServices {
    pub async fn diagnostics(&self) -> DiagnosticsSnapshot {
        self.diagnostics.read().await.clone()
    }

    pub(crate) async fn update_diagnostics(
        &self,
        targets: &[ConfiguredTarget],
        errors: &[TargetError],
    ) {
        let selected = join_all(targets.iter().map(|configured| async move {
            self.rac
                .chosen_candidate(configured.target.ras.as_str())
                .await
                .map(|candidate| {
                    let components = candidate.version.components();
                    SelectedRac {
                        cluster: configured.target.alias.clone(),
                        ras_address: configured.target.ras.clone(),
                        path: candidate.path,
                        version: PlatformVersion::new(
                            components[0],
                            components[1],
                            components[2],
                            components[3],
                        ),
                        origin: candidate.origin.code().to_owned(),
                    }
                })
        }))
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

        let mut state = self.diagnostics.write().await;
        state.selected_rac = selected;
        state.target_errors = errors.to_vec();
        state.updated_at = Some(Utc::now());
    }
}
