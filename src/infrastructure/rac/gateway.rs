use std::{collections::HashMap, fmt, sync::Arc, time::Duration};

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    RacArgumentBuilder, RacArguments, RacCandidate, RacCredentials, RacError, RacErrorKind,
    RacLocator, RacOutputDecoder, RacProcessRunner, RacRecord, RacRecordParser, RacVersionProbe,
    SearchPolicy, classify_diagnostic,
};

#[derive(Clone)]
pub struct RacGateway {
    runner: RacProcessRunner,
    locator: RacLocator,
    arguments: RacArgumentBuilder,
    selected: Arc<Mutex<HashMap<String, RacCandidate>>>,
}

impl RacGateway {
    pub fn new(timeout: Duration) -> Self {
        Self::with_runner(RacProcessRunner::new(timeout))
    }

    pub fn with_runner(runner: RacProcessRunner) -> Self {
        let locator = RacLocator::new(RacVersionProbe::new(runner.clone()));
        Self::from_parts(runner, locator)
    }

    pub fn from_parts(runner: RacProcessRunner, locator: RacLocator) -> Self {
        Self {
            runner,
            locator,
            arguments: RacArgumentBuilder::new(),
            selected: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn runner(&self) -> &RacProcessRunner {
        &self.runner
    }

    pub fn locator(&self) -> &RacLocator {
        &self.locator
    }

    pub async fn chosen_candidate(&self, ras_address: &str) -> Option<RacCandidate> {
        self.selected
            .lock()
            .await
            .get(&endpoint_cache_key(ras_address))
            .cloned()
    }

    pub async fn clear_chosen_candidates(&self) {
        self.selected.lock().await.clear();
    }

    pub async fn cluster_list(
        &self,
        ras_address: &str,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let arguments = self.arguments.cluster_list(ras_address);
        self.execute(ras_address, search_policy, &arguments, cancellation)
            .await
    }

    pub async fn cluster_info(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let arguments = self
            .arguments
            .cluster_info(ras_address, cluster_id, cluster_credentials);
        self.execute(ras_address, search_policy, &arguments, cancellation)
            .await
    }

    pub async fn infobase_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let arguments = self
            .arguments
            .infobase_list(ras_address, cluster_id, cluster_credentials);
        self.execute(ras_address, search_policy, &arguments, cancellation)
            .await
    }

    pub async fn session_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let arguments = self
            .arguments
            .session_list(ras_address, cluster_id, cluster_credentials);
        self.execute(ras_address, search_policy, &arguments, cancellation)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn session_terminate(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        session_id: Uuid,
        message: Option<&str>,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let arguments = self.arguments.session_terminate(
            ras_address,
            cluster_id,
            session_id,
            message,
            cluster_credentials,
        );
        self.execute(ras_address, search_policy, &arguments, cancellation)
            .await
    }

    pub async fn connection_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let arguments =
            self.arguments
                .connection_list(ras_address, cluster_id, cluster_credentials);
        self.execute(ras_address, search_policy, &arguments, cancellation)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connection_disconnect(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        process_id: Uuid,
        connection_id: Uuid,
        cluster_credentials: &RacCredentials,
        infobase_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let arguments = self.arguments.connection_disconnect(
            ras_address,
            cluster_id,
            process_id,
            connection_id,
            cluster_credentials,
            infobase_credentials,
        );
        self.execute(ras_address, search_policy, &arguments, cancellation)
            .await
    }

    pub async fn process_list(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let arguments = self
            .arguments
            .process_list(ras_address, cluster_id, cluster_credentials);
        self.execute(ras_address, search_policy, &arguments, cancellation)
            .await
    }

    pub async fn process_turn_off(
        &self,
        ras_address: &str,
        cluster_id: Uuid,
        process_id: Uuid,
        cluster_credentials: &RacCredentials,
        search_policy: &SearchPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let arguments = self.arguments.process_turn_off(
            ras_address,
            cluster_id,
            process_id,
            cluster_credentials,
        );
        self.execute(ras_address, search_policy, &arguments, cancellation)
            .await
    }

    async fn execute(
        &self,
        ras_address: &str,
        search_policy: &SearchPolicy,
        arguments: &RacArguments,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let cache_key = endpoint_cache_key(ras_address);
        let cached = self.selected.lock().await.get(&cache_key).cloned();
        let mut failed_cached = None;

        if let Some(candidate) = cached.filter(|candidate| search_policy.accepts_cached(candidate))
        {
            match self
                .execute_with_candidate(&candidate, arguments, cancellation)
                .await
            {
                Ok(records) => return Ok(records),
                Err(error) if error.allows_version_fallback() => {
                    self.selected.lock().await.remove(&cache_key);
                    failed_cached = Some((candidate, error));
                }
                Err(error) => return Err(error),
            }
        }

        let candidates = self
            .locator
            .find_candidates(search_policy, cancellation)
            .await?;
        let mut last_protocol_error = failed_cached.as_ref().map(|(_, error)| error.clone());

        for candidate in candidates {
            if failed_cached
                .as_ref()
                .is_some_and(|(failed, _)| failed.path == candidate.path)
            {
                continue;
            }

            match self
                .execute_with_candidate(&candidate, arguments, cancellation)
                .await
            {
                Ok(records) => {
                    self.selected.lock().await.insert(cache_key, candidate);
                    return Ok(records);
                }
                Err(error) if error.allows_version_fallback() => {
                    last_protocol_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }

        Err(last_protocol_error
            .unwrap_or_else(|| RacError::new(RacErrorKind::ProtocolIncompatible)))
    }

    async fn execute_with_candidate(
        &self,
        candidate: &RacCandidate,
        arguments: &RacArguments,
        cancellation: &CancellationToken,
    ) -> Result<Vec<RacRecord>, RacError> {
        let output = self
            .runner
            .run(&candidate.path, arguments, cancellation)
            .await
            .map_err(RacError::from_process)?;

        if !output.status().success() {
            let stderr = RacOutputDecoder::decode(output.stderr());
            let stdout = RacOutputDecoder::decode(output.stdout());
            let mut kind = classify_diagnostic(stderr.text());
            if kind == RacErrorKind::Unknown {
                kind = classify_diagnostic(stdout.text());
            }
            return Err(RacError::command_failed(
                kind,
                output.status().code(),
                output.invocation().clone(),
            ));
        }

        let stdout = RacOutputDecoder::decode(output.stdout());
        RacRecordParser::parse(stdout.text()).map_err(|_| {
            RacError::with_invocation(RacErrorKind::Parse, output.invocation().clone())
        })
    }
}

impl Default for RacGateway {
    fn default() -> Self {
        Self::with_runner(RacProcessRunner::default())
    }
}

impl fmt::Debug for RacGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RacGateway")
            .field("timeout", &self.runner.timeout())
            .finish_non_exhaustive()
    }
}

fn endpoint_cache_key(ras_address: &str) -> String {
    ras_address.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_cache_is_case_insensitive() {
        assert_eq!(
            endpoint_cache_key(" RAS-SERVER.EXAMPLE:1545 "),
            endpoint_cache_key("ras-server.example:1545")
        );
    }
}
