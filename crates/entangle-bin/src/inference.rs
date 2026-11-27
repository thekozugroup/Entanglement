//! Operator-configured OpenAI-compatible inference over the worker's signed stream.

use crate::config::InferenceConfig;
use anyhow::{bail, ensure, Context, Result};
use entangle_runtime::Kernel;
use entangle_scheduler::stream::{StreamExecutor, StreamOutput};
use entangle_signing::IdentityKeyPair;
use entangle_types::{
    peer_id::PeerId,
    plugin_id::PluginId,
    task::{IntegrityPolicy, StreamingTask},
    tier::Tier,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, header, Method, Request, Uri};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use serde::Deserialize;
use serde_json::json;
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_MODEL_LIST_BYTES: usize = 128 * 1024;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_TOKENS: u32 = 4096;
const MAX_SSE_EVENT_BYTES: usize = 64 * 1024;
const MAX_SSE_BYTES: usize = 8 * 1024 * 1024;

pub(crate) struct Inference {
    kernel: Arc<Kernel>,
    provider: Provider,
    id: PluginId,
    worker: PeerId,
    active: Semaphore,
}

impl Inference {
    pub(crate) fn new(
        config: &InferenceConfig,
        identity: &IdentityKeyPair,
        kernel: Arc<Kernel>,
    ) -> Result<Self> {
        Ok(Self {
            kernel,
            provider: Provider::new(config)?,
            id: format!(
                "{}/openai-inference@0.1.0",
                identity.public().fingerprint_hex()
            )
            .parse()?,
            worker: PeerId::from_public_key_bytes(identity.public().as_bytes()),
            active: Semaphore::new(1),
        })
    }

    pub(crate) fn id(&self) -> &PluginId {
        &self.id
    }

    fn enabled(&self) -> bool {
        self.kernel.broker().policy().max_tier_allowed == Tier::Native
    }
}

#[async_trait::async_trait]
impl StreamExecutor for Inference {
    async fn streaming_plugins(&self) -> Vec<PluginId> {
        if !self.enabled() {
            return Vec::new();
        }
        let readiness = tokio::time::timeout(HEALTH_TIMEOUT, async {
            let _tier = self.kernel.native_service_lease().await?;
            self.provider.check_ready().await
        })
        .await;
        if matches!(readiness, Ok(Ok(()))) && self.enabled() {
            vec![self.id.clone()]
        } else {
            Vec::new()
        }
    }

    async fn produce(
        &self,
        task: StreamingTask,
        input: Vec<u8>,
        output: StreamOutput,
    ) -> std::result::Result<(), String> {
        if task.plugin != self.id {
            return self.kernel.produce(task, input, output).await;
        }
        self.run(task, &input, output)
            .await
            .map_err(|error| error.to_string())
    }
}

impl Inference {
    async fn run(&self, task: StreamingTask, input: &[u8], output: StreamOutput) -> Result<()> {
        ensure!(
            matches!(&task.integrity, IntegrityPolicy::TrustedExecutor { allowlist } if allowlist.contains(&self.worker)),
            "local inference requires a TrustedExecutor policy naming this worker"
        );
        ensure!(
            input.len() <= MAX_INPUT_BYTES,
            "inference input exceeds 64 KiB"
        );
        let input: Input = serde_json::from_slice(input).context("invalid inference input")?;
        input.validate()?;
        let _active = self
            .active
            .try_acquire()
            .context("local inference worker is busy")?;
        let _tier = self.kernel.native_service_lease().await?;
        self.provider.ready().await?;
        let mut remaining = task.channel.max_total_bytes;
        self.provider
            .generate(input, |token| {
                let output = output.clone();
                let max_chunk = task.channel.max_chunk_bytes as usize;
                let len = token.len() as u64;
                let allowed = len <= remaining;
                remaining = remaining.saturating_sub(len);
                async move {
                    ensure!(allowed, "total-bytes");
                    for chunk in token.as_bytes().chunks(max_chunk) {
                        output
                            .send_chunk(chunk.to_vec())
                            .await
                            .map_err(anyhow::Error::msg)?;
                    }
                    Ok(())
                }
            })
            .await
    }
}

#[derive(Clone, Copy)]
enum Endpoint {
    Chat,
    Completion,
}

struct Provider {
    client: Client<HttpConnector, Full<Bytes>>,
    endpoint: Uri,
    mode: Endpoint,
    models: Uri,
    model: String,
    auth: Option<header::HeaderValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    prompt: String,
    max_tokens: u32,
    temperature: Option<f64>,
}

impl Input {
    fn validate(&self) -> Result<()> {
        ensure!(!self.prompt.is_empty(), "inference prompt is empty");
        ensure!(
            (1..=MAX_TOKENS).contains(&self.max_tokens),
            "inference max_tokens must be in 1..={MAX_TOKENS}"
        );
        ensure!(
            self.temperature
                .is_none_or(|value| (0.0..=2.0).contains(&value)),
            "inference temperature must be in 0..=2"
        );
        Ok(())
    }
}

impl Provider {
    fn new(config: &InferenceConfig) -> Result<Self> {
        let endpoint: Uri = config
            .endpoint
            .parse()
            .context("invalid inference endpoint URL")?;
        let authority = endpoint
            .authority()
            .context("missing inference endpoint host")?;
        ensure!(
            endpoint.scheme_str() == Some("http")
                && authority.host().trim_matches(['[', ']']).parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
                && (authority.as_str() == authority.host()
                    || authority.port_u16().is_some_and(|port| port != 0))
                && !authority.as_str().contains('@')
                && endpoint.query().is_none()
                && !config.endpoint.contains('#'),
            "inference endpoint must be a literal loopback HTTP URL without credentials, query or fragment"
        );
        let mode = match endpoint.path() {
            "/v1/chat/completions" => Endpoint::Chat,
            "/v1/completions" => Endpoint::Completion,
            _ => bail!("inference endpoint path must be /v1/chat/completions or /v1/completions"),
        };
        ensure!(
            !config.model.trim().is_empty()
                && config.model.len() <= 512
                && !config.model.chars().any(char::is_control),
            "inference model must be a nonempty ID of at most 512 bytes without control characters"
        );
        let auth = config
            .token_env
            .as_ref()
            .map(|name| {
                let token = std::env::var(name)
                    .context("reading the inference bearer token environment variable")?;
                ensure!(
                    !token.is_empty() && token.len() <= 4096,
                    "invalid inference bearer token length"
                );
                let mut auth = header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .context("invalid inference bearer token")?;
                auth.set_sensitive(true);
                Ok::<_, anyhow::Error>(auth)
            })
            .transpose()?;
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(HEALTH_TIMEOUT));
        let client = Client::builder(TokioExecutor::new())
            .retry_canceled_requests(false)
            .build(connector);
        let models = Uri::builder()
            .scheme("http")
            .authority(authority.clone())
            .path_and_query("/v1/models")
            .build()?;
        Ok(Self {
            client,
            endpoint,
            mode,
            models,
            model: config.model.clone(),
            auth,
        })
    }

    fn request(&self, method: Method, uri: &Uri) -> hyper::http::request::Builder {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(auth) = &self.auth {
            request = request.header(header::AUTHORIZATION, auth.clone());
        }
        request
    }

    async fn ready(&self) -> Result<()> {
        tokio::time::timeout(HEALTH_TIMEOUT, self.check_ready())
            .await
            .context("local inference model inventory timed out")?
    }

    async fn check_ready(&self) -> Result<()> {
        #[derive(Deserialize)]
        struct Models {
            data: Vec<Model>,
        }
        #[derive(Deserialize)]
        struct Model {
            id: String,
        }
        let mut response = self
            .client
            .request(
                self.request(Method::GET, &self.models)
                    .body(Full::default())?,
            )
            .await
            .context("local inference backend is unavailable")?;
        ensure!(
            response.status().is_success(),
            "local inference model inventory returned HTTP {}",
            response.status()
        );
        let mut bytes = Vec::new();
        while let Some(frame) = response.body_mut().frame().await {
            let Ok(chunk) = frame
                .context("reading local inference model inventory")?
                .into_data()
            else {
                continue;
            };
            ensure!(
                chunk.len() <= MAX_MODEL_LIST_BYTES - bytes.len(),
                "local inference model inventory exceeds 128 KiB"
            );
            bytes.extend_from_slice(&chunk);
        }
        let models: Models =
            serde_json::from_slice(&bytes).context("invalid local inference model inventory")?;
        ensure!(
            models.data.iter().any(|model| model.id == self.model),
            "configured local inference model is not ready"
        );
        Ok(())
    }

    async fn generate<F, Fut>(&self, input: Input, mut send: F) -> Result<()>
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let mut body =
            json!({ "model": self.model, "stream": true, "max_tokens": input.max_tokens });
        match self.mode {
            Endpoint::Chat => {
                body["messages"] = json!([{ "role": "user", "content": input.prompt }])
            }
            Endpoint::Completion => body["prompt"] = json!(input.prompt),
        }
        if let Some(temperature) = input.temperature {
            body["temperature"] = json!(temperature);
        }
        let request = self
            .request(Method::POST, &self.endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "text/event-stream")
            .body(Full::new(Bytes::from(serde_json::to_vec(&body)?)))?;
        let mut response = self
            .client
            .request(request)
            .await
            .context("local inference request failed")?;
        ensure!(
            response.status().is_success(),
            "local inference backend returned HTTP {}",
            response.status()
        );
        ensure!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream")),
            "local inference backend did not return text/event-stream"
        );

        let mut sse = Sse::default();
        let mut wire_bytes = 0;
        let mut completed = false;
        while let Some(frame) = response.body_mut().frame().await {
            let Ok(chunk) = frame.context("reading local inference stream")?.into_data() else {
                continue;
            };
            wire_bytes += chunk.len();
            ensure!(
                wire_bytes <= MAX_SSE_BYTES,
                "local inference stream exceeds 8 MiB"
            );
            for byte in chunk {
                let Some(event) = sse.feed(byte)? else {
                    continue;
                };
                if event == b"[DONE]" {
                    return Ok(());
                }
                let payload: Frame =
                    serde_json::from_slice(&event).context("invalid local inference event")?;
                if let Some(choice) = payload.choices.into_iter().find(|choice| choice.index == 0) {
                    completed |= choice.finish_reason.is_some();
                    let token = match self.mode {
                        Endpoint::Chat => choice.delta.and_then(|delta| delta.content),
                        Endpoint::Completion => choice.text,
                    };
                    if let Some(token) = token.filter(|token| !token.is_empty()) {
                        send(token).await?;
                    }
                }
            }
        }
        ensure!(completed, "local inference stream ended before completion");
        Ok(())
    }
}

#[derive(Deserialize)]
struct Frame {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    index: u32,
    delta: Option<Delta>,
    text: Option<String>,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct Delta {
    content: Option<String>,
}

/// Byte-based event framing handles UTF-8 characters split across HTTP chunks.
#[derive(Default)]
struct Sse {
    line: Vec<u8>,
    event: Vec<u8>,
    saw_first_line: bool,
    skip_lf: bool,
}

impl Sse {
    fn feed(&mut self, byte: u8) -> Result<Option<Vec<u8>>> {
        if std::mem::take(&mut self.skip_lf) && byte == b'\n' {
            return Ok(None);
        }
        if byte != b'\n' && byte != b'\r' {
            ensure!(
                self.line.len() < MAX_SSE_EVENT_BYTES,
                "local inference SSE line exceeds 64 KiB"
            );
            self.line.push(byte);
            return Ok(None);
        }
        self.skip_lf = byte == b'\r';
        let mut line = self.line.as_slice();
        if !std::mem::replace(&mut self.saw_first_line, true) {
            line = line.strip_prefix(b"\xef\xbb\xbf").unwrap_or(line);
        }
        let result = if line.is_empty() && !self.event.is_empty() {
            let mut event = std::mem::take(&mut self.event);
            event.pop();
            Some(event)
        } else {
            let data = line
                .strip_prefix(b"data:")
                .or_else(|| (line == b"data").then_some(&[][..]));
            if let Some(data) = data {
                let data = data.strip_prefix(b" ").unwrap_or(data);
                ensure!(
                    self.event.len() + data.len() < MAX_SSE_EVENT_BYTES,
                    "local inference SSE event exceeds 64 KiB"
                );
                self.event.extend_from_slice(data);
                self.event.push(b'\n');
            }
            None
        };
        self.line.clear();
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
