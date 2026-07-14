use super::{
    config::{ModelApi, ModelConfig},
    Result, ServiceError,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const MAX_MODEL_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Completion {
    pub text: String,
    pub completion_tokens: u32,
}

#[derive(Clone)]
pub struct ModelBackend {
    client: reqwest::Client,
    api: ModelApi,
    base_url: String,
    model: String,
    api_key: Option<String>,
    system_prompt: String,
    num_gpu: Option<u32>,
}

#[derive(Deserialize)]
struct ModelList {
    data: Vec<ModelEntry>,
}

#[derive(Deserialize)]
struct ModelEntry {
    id: String,
}

#[derive(Serialize)]
struct OpenAiCompletionRequest<'a> {
    model: &'a str,
    messages: [Message<'a>; 2],
    max_tokens: u32,
    temperature: u8,
    stream: bool,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'static str,
    content: &'a str,
}

#[derive(Clone, Copy, Serialize)]
struct OllamaOptions {
    temperature: u8,
    num_predict: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_gpu: Option<u32>,
}

#[derive(Deserialize)]
struct CompletionResponse {
    choices: Vec<Choice>,
    usage: Option<Usage>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: String,
}

#[derive(Deserialize)]
struct Usage {
    completion_tokens: u32,
}

#[derive(Serialize)]
struct OllamaCompletionRequest<'a> {
    model: &'a str,
    messages: [Message<'a>; 2],
    stream: bool,
    options: OllamaOptions,
}

#[derive(Deserialize)]
struct OllamaModelList {
    models: Vec<OllamaModelEntry>,
}

#[derive(Deserialize)]
struct OllamaModelEntry {
    name: String,
}

#[derive(Deserialize)]
struct OllamaCompletionResponse {
    message: ResponseMessage,
    eval_count: Option<u32>,
}

impl ModelBackend {
    pub fn new(config: &ModelConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|error| ServiceError::Internal(format!("HTTP client: {error}")))?;
        let mut base_url = config.base_url.trim_end_matches('/').to_owned();
        if config.api == ModelApi::Ollama {
            base_url = base_url.strip_suffix("/v1").unwrap_or(&base_url).to_owned();
        }
        Ok(Self {
            client,
            api: config.api,
            base_url,
            model: config.model.clone(),
            api_key: config.api_key.clone(),
            system_prompt: config.system_prompt.clone(),
            num_gpu: config.num_gpu,
        })
    }

    #[must_use]
    pub fn model_name(&self) -> &str {
        &self.model
    }

    pub async fn health(&self) -> Result<()> {
        let path = match self.api {
            ModelApi::OpenAi => "models",
            ModelApi::Ollama => "api/tags",
        };
        let request = self.authorize(
            self.client
                .get(format!("{}/{path}", self.base_url))
                .header(ACCEPT, "application/json"),
        );
        let response = request
            .send()
            .await
            .map_err(|error| ServiceError::Backend(format!("model health request: {error}")))?;
        if !response.status().is_success() {
            return Err(ServiceError::Backend(format!(
                "model health returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let body = bounded_body(response).await?;
        let installed = match self.api {
            ModelApi::OpenAi => {
                let models: ModelList = serde_json::from_slice(&body).map_err(|error| {
                    ServiceError::Backend(format!("invalid model list: {error}"))
                })?;
                models.data.iter().any(|entry| entry.id == self.model)
            }
            ModelApi::Ollama => {
                let models: OllamaModelList = serde_json::from_slice(&body).map_err(|error| {
                    ServiceError::Backend(format!("invalid Ollama model list: {error}"))
                })?;
                models.models.iter().any(|entry| entry.name == self.model)
            }
        };
        if !installed {
            return Err(ServiceError::Backend(format!(
                "configured model {} is not installed",
                self.model
            )));
        }
        Ok(())
    }

    pub async fn complete(&self, prompt: &str, maximum_output_tokens: u32) -> Result<Completion> {
        let (text, reported_tokens) = match self.api {
            ModelApi::OpenAi => self.complete_open_ai(prompt, maximum_output_tokens).await?,
            ModelApi::Ollama => self.complete_ollama(prompt, maximum_output_tokens).await?,
        };
        if text.trim().is_empty() {
            return Err(ServiceError::Backend(
                "model returned an empty completion".to_owned(),
            ));
        }
        let estimated = text.chars().count().div_ceil(4).max(1);
        let estimated = u32::try_from(estimated).unwrap_or(u32::MAX);
        let completion_tokens = reported_tokens
            .filter(|tokens| *tokens != 0)
            .unwrap_or(estimated);
        if completion_tokens > maximum_output_tokens {
            return Err(ServiceError::Backend(
                "model exceeded the quoted output-token bound".to_owned(),
            ));
        }
        Ok(Completion {
            text,
            completion_tokens,
        })
    }

    async fn complete_open_ai(
        &self,
        prompt: &str,
        maximum_output_tokens: u32,
    ) -> Result<(String, Option<u32>)> {
        let body = OpenAiCompletionRequest {
            model: &self.model,
            messages: self.messages(prompt),
            max_tokens: maximum_output_tokens,
            temperature: 0,
            stream: false,
        };
        let response = self
            .authorize(
                self.client
                    .post(format!("{}/chat/completions", self.base_url))
                    .header(ACCEPT, "application/json")
                    .header(CONTENT_TYPE, "application/json")
                    .json(&body),
            )
            .send()
            .await
            .map_err(|error| ServiceError::Backend(format!("model completion request: {error}")))?;
        let body = self.completion_body(response).await?;
        let mut completion: CompletionResponse = serde_json::from_slice(&body)
            .map_err(|error| ServiceError::Backend(format!("invalid completion JSON: {error}")))?;
        if completion.choices.len() != 1 {
            return Err(ServiceError::Backend(
                "model returned anything other than one choice".to_owned(),
            ));
        }
        let text = completion.choices.remove(0).message.content;
        Ok((text, completion.usage.map(|usage| usage.completion_tokens)))
    }

    async fn complete_ollama(
        &self,
        prompt: &str,
        maximum_output_tokens: u32,
    ) -> Result<(String, Option<u32>)> {
        let body = OllamaCompletionRequest {
            model: &self.model,
            messages: self.messages(prompt),
            stream: false,
            options: OllamaOptions {
                temperature: 0,
                num_predict: maximum_output_tokens,
                num_gpu: self.num_gpu,
            },
        };
        let response = self
            .authorize(
                self.client
                    .post(format!("{}/api/chat", self.base_url))
                    .header(ACCEPT, "application/json")
                    .header(CONTENT_TYPE, "application/json")
                    .json(&body),
            )
            .send()
            .await
            .map_err(|error| {
                ServiceError::Backend(format!("Ollama completion request: {error}"))
            })?;
        let body = self.completion_body(response).await?;
        let completion: OllamaCompletionResponse =
            serde_json::from_slice(&body).map_err(|error| {
                ServiceError::Backend(format!("invalid Ollama completion JSON: {error}"))
            })?;
        Ok((completion.message.content, completion.eval_count))
    }

    fn messages<'a>(&'a self, prompt: &'a str) -> [Message<'a>; 2] {
        [
            Message {
                role: "system",
                content: &self.system_prompt,
            },
            Message {
                role: "user",
                content: prompt,
            },
        ]
    }

    async fn completion_body(&self, response: reqwest::Response) -> Result<Vec<u8>> {
        if !response.status().is_success() {
            return Err(ServiceError::Backend(format!(
                "model completion returned HTTP {}",
                response.status().as_u16()
            )));
        }
        bounded_body(response).await
    }

    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(key) => request.header(AUTHORIZATION, format!("Bearer {key}")),
            None => request,
        }
    }
}

async fn bounded_body(response: reqwest::Response) -> Result<Vec<u8>> {
    let body = response
        .bytes()
        .await
        .map_err(|error| ServiceError::Backend(format!("model response body: {error}")))?;
    if body.len() > MAX_MODEL_RESPONSE_BYTES {
        return Err(ServiceError::Backend(
            "model response exceeded 2 MiB".to_owned(),
        ));
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use axum::{
        extract::State,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    async fn capture_ollama_request(
        State(captured): State<Arc<Mutex<Option<Value>>>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        *captured.lock().await = Some(body);
        Json(json!({
            "message": {"content": "test-only answer"},
            "eval_count": 4
        }))
    }

    #[tokio::test]
    async fn ollama_backend_uses_native_api_and_cpu_option() {
        let captured = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route(
                "/api/tags",
                get(|| async {
                    Json(json!({
                        "models": [{"name": "qwen2.5:0.5b"}]
                    }))
                }),
            )
            .route("/api/chat", post(capture_ollama_request))
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let backend = ModelBackend::new(&ModelConfig {
            api: ModelApi::Ollama,
            base_url: format!("http://{address}/v1"),
            model: "qwen2.5:0.5b".to_owned(),
            api_key: None,
            system_prompt: "test-only system".to_owned(),
            timeout_ms: 5_000,
            num_gpu: Some(0),
        })
        .unwrap();

        backend.health().await.unwrap();
        let completion = backend.complete("question", 64).await.unwrap();
        assert_eq!(completion.text, "test-only answer");
        assert_eq!(completion.completion_tokens, 4);

        let request = captured.lock().await.clone().unwrap();
        assert_eq!(request["model"], "qwen2.5:0.5b");
        assert_eq!(request["messages"][0]["role"], "system");
        assert_eq!(request["messages"][1]["content"], "question");
        assert_eq!(request["options"]["temperature"], 0);
        assert_eq!(request["options"]["num_predict"], 64);
        assert_eq!(request["options"]["num_gpu"], 0);
        server.abort();
    }
}
