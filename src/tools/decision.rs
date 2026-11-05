//! Operator-enabled inference to fixed official endpoints. This is a host provider call,
//! not target-scope HTTP traffic. Returned judgments never change grants or finding verdicts.

use std::{collections::BTreeMap, time::Duration};

use futures_util::StreamExt;
use reqwest::{header::HeaderValue, Client};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    provider::{Provenance, ToolSchema},
    sandbox::Sandbox,
    tools::{Tool, ToolResult},
};

const MAX_REQUEST: usize = 64 * 1024;
const MAX_RESPONSE: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Backend {
    Jev,
    Clef,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Args {
    backend: Backend,
    state: Value,
    questions: BTreeMap<String, Question>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Question {
    Choice {
        instructions: String,
        criteria: BTreeMap<String, String>,
    },
    Score {
        instructions: String,
        criteria: Vec<String>,
    },
    Noul {
        instructions: String,
    },
}

impl Args {
    fn parse(value: Value) -> Result<Self, String> {
        if serde_json::to_vec(&value)
            .map_err(|_| "invalid arguments")?
            .len()
            > MAX_REQUEST
        {
            return Err("decision request exceeds 64 KiB".into());
        }
        let args: Self = serde_json::from_value(value).map_err(|_| {
            "expected backend, state, and typed questions; unknown fields are not accepted"
        })?;
        if !matches!(
            args.state,
            Value::String(_) | Value::Object(_) | Value::Array(_)
        ) {
            return Err("state must be text, an object, or an array".into());
        }
        if args.questions.is_empty() || args.questions.len() > 64 {
            return Err("provide 1 to 64 questions".into());
        }
        for (name, question) in &args.questions {
            if name.is_empty()
                || name.len() > 100
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            {
                return Err("question ids must be 1 to 100 ASCII letters, digits, underscores, dots, or hyphens".into());
            }
            let instructions = match question {
                Question::Choice {
                    instructions,
                    criteria,
                } => {
                    if !(2..=255).contains(&criteria.len())
                        || criteria.keys().any(|k| k.trim().is_empty())
                    {
                        return Err("choice requires 2 to 255 named options".into());
                    }
                    instructions
                }
                Question::Score {
                    instructions,
                    criteria,
                } => {
                    if !(2..=10).contains(&criteria.len())
                        || criteria.iter().any(|s| s.trim().is_empty())
                    {
                        return Err("score requires 2 to 10 nonempty rubric levels".into());
                    }
                    instructions
                }
                Question::Noul { instructions } => instructions,
            };
            if instructions.trim().is_empty() {
                return Err("each question needs nonempty instructions".into());
            }
        }
        Ok(args)
    }
}

// Never derive Debug or Serialize: this holds the provider credential.
struct Endpoint {
    url: String,
    model: String,
    authorization: HeaderValue,
}

fn required(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<String, String> {
    get(name)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

fn configured(backend: Backend, get: &impl Fn(&str) -> Option<String>) -> Result<Endpoint, String> {
    let (enabled, key) = match backend {
        Backend::Jev => ("BEE_DECISION_JEV_ENABLED", "TYPESAFE_API_KEY"),
        Backend::Clef => ("BEE_DECISION_CLEF_ENABLED", "CLOUDFLARE_API_TOKEN"),
    };
    if get(enabled).as_deref() != Some("1") {
        return Err(format!("backend disabled; operator must set {enabled}=1"));
    }
    let (url, model) = match backend {
        Backend::Jev => {
            let model = get("BEE_DECISION_JEV_MODEL").unwrap_or_else(|| "jev-latest".into());
            if !model.starts_with("jev-")
                || model.len() > 100
                || !model
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
            {
                return Err(
                    "BEE_DECISION_JEV_MODEL must be a Jev model name from TypeSafe's catalog"
                        .into(),
                );
            }
            ("https://api.typesafe.ai/v1/systemone".into(), model)
        }
        Backend::Clef => {
            let account = required(get, "CLOUDFLARE_ACCOUNT_ID")?;
            if account.len() != 32 || !account.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("CLOUDFLARE_ACCOUNT_ID must be 32 hexadecimal characters".into());
            }
            let model = get("BEE_DECISION_CLEF_MODEL").unwrap_or_else(|| "clef-flash".into());
            if !matches!(model.as_str(), "clef" | "clef-flash") {
                return Err("BEE_DECISION_CLEF_MODEL must be clef or clef-flash".into());
            }
            (format!("https://api.cloudflare.com/client/v4/accounts/{account}/ai/run/@cf/cloudflare/{model}"), model)
        }
    };
    let mut authorization = HeaderValue::from_str(&format!("Bearer {}", required(get, key)?))
        .map_err(|_| format!("{key} is not a valid bearer credential"))?;
    authorization.set_sensitive(true);
    Ok(Endpoint {
        url,
        model,
        authorization,
    })
}

pub struct DecisionTool {
    jev: Result<Endpoint, String>,
    clef: Result<Endpoint, String>,
    client: Result<Client, String>,
}

impl DecisionTool {
    pub fn from_env() -> Self {
        Self::configure(|name| std::env::var(name).ok())
    }

    fn configure(get: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            jev: configured(Backend::Jev, &get),
            clef: configured(Backend::Clef, &get),
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .connect_timeout(Duration::from_secs(10))
                .timeout(TIMEOUT)
                .build()
                .map_err(|_| "could not initialize decision HTTP client".into()),
        }
    }

    async fn evaluate(&self, args: &Args) -> Result<Value, String> {
        let endpoint = match args.backend {
            Backend::Jev => &self.jev,
            Backend::Clef => &self.clef,
        }
        .as_ref()
        .map_err(Clone::clone)?;
        let client = self.client.as_ref().map_err(Clone::clone)?;
        let body = serde_json::to_vec(
            &json!({"model":endpoint.model, "state":args.state, "questions":args.questions}),
        )
        .map_err(|_| "could not encode decision request")?;
        if body.len() > MAX_REQUEST {
            return Err("decision request exceeds 64 KiB".into());
        }
        // One request only: retrying an unknown outcome can bill the operator twice.
        let response = client
            .post(&endpoint.url)
            .header(
                reqwest::header::AUTHORIZATION,
                endpoint.authorization.clone(),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| "decision provider transport failure")?;
        if !response.status().is_success() {
            return Err(format!(
                "decision provider returned HTTP {}",
                response.status().as_u16()
            ));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE as u64)
        {
            return Err("decision response exceeds 1 MiB".into());
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "decision response interrupted")?;
            if chunk.len() > MAX_RESPONSE - bytes.len() {
                return Err("decision response exceeds 1 MiB".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let wire: Value = serde_json::from_slice(&bytes)
            .map_err(|_| "decision provider returned invalid JSON")?;
        normalize(args, wire)
    }
}

fn probability(value: &Value) -> bool {
    value
        .as_f64()
        .is_some_and(|p| p.is_finite() && (0.0..=1.0).contains(&p))
}

fn distribution(value: &Value, keys: &[String]) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    map.len() == keys.len()
        && keys.iter().all(|k| map.get(k).is_some_and(probability))
        && (map.values().filter_map(Value::as_f64).sum::<f64>() - 1.0).abs() <= 0.01
}

fn normalize(args: &Args, wire: Value) -> Result<Value, String> {
    let response = if args.backend == Backend::Clef {
        if wire.get("success") != Some(&Value::Bool(true)) {
            return Err("Workers AI reported an unsuccessful request".into());
        }
        wire.get("result")
            .ok_or("Workers AI response has no result")?
    } else {
        &wire
    };
    let model = response
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .ok_or("decision response has no model identity")?;
    let answers = response
        .get("answers")
        .and_then(Value::as_object)
        .ok_or("decision response has no answers")?;
    if answers.len() != args.questions.len() {
        return Err("decision response does not match requested questions".into());
    }
    for (name, question) in &args.questions {
        let answer = answers
            .get(name)
            .ok_or("decision response is missing a requested answer")?;
        let valid = match question {
            Question::Noul { .. } => {
                answer.get("type").and_then(Value::as_str) == Some("noul")
                    && answer.get("noul").is_some_and(probability)
            }
            Question::Choice { criteria, .. } => {
                answer.get("type").and_then(Value::as_str) == Some("choice")
                    && answer
                        .get("choice")
                        .and_then(Value::as_str)
                        .is_some_and(|v| criteria.contains_key(v))
                    && answer.get("confidence").is_some_and(probability)
                    && distribution(
                        &answer["probabilities"],
                        &criteria.keys().cloned().collect::<Vec<_>>(),
                    )
            }
            Question::Score { criteria, .. } => {
                answer.get("type").and_then(Value::as_str) == Some("score")
                    && answer
                        .get("score")
                        .and_then(Value::as_f64)
                        .is_some_and(|v| {
                            v.is_finite() && v >= 0.0 && v <= (criteria.len() - 1) as f64
                        })
                    && answer.get("confidence").is_some_and(probability)
                    && distribution(
                        &answer["probabilities"],
                        &(0..criteria.len())
                            .map(|i| i.to_string())
                            .collect::<Vec<_>>(),
                    )
            }
        };
        if !valid {
            return Err(
                "decision response has an invalid answer or probability distribution".into(),
            );
        }
    }
    let usage = response
        .get("usage")
        .filter(|v| v.is_object())
        .ok_or("decision response has no usage")?;
    if usage.get("input_tokens").and_then(Value::as_u64).is_none() {
        return Err("decision response has invalid usage".into());
    }
    Ok(json!({"backend":args.backend,"model":model,"answers":answers,"usage":usage}))
}

#[async_trait::async_trait]
impl Tool for DecisionTool {
    fn name(&self) -> &'static str {
        "decision_evaluate"
    }

    fn schema(&self) -> ToolSchema {
        let question = |kind: &str, criteria: Option<Value>| {
            let mut properties = json!({"type":{"type":"string","enum":[kind]},"instructions":{"type":"string","minLength":1}});
            let mut required = vec!["type", "instructions"];
            if let Some(criteria) = criteria {
                properties["criteria"] = criteria;
                required.push("criteria");
            }
            json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
        };
        ToolSchema {
            name: self.name().into(),
            description: "Ask an operator-enabled Jev or Clef decision model to judge supplied evidence. Returns typed answers, probabilities and usage, not new evidence or permission. Text/JSON only; at most 64 questions and 64 KiB per request.".into(),
            parameters: json!({"type":"object","additionalProperties":false,"required":["backend","state","questions"],"properties":{
                "backend":{"type":"string","enum":["jev","clef"]},
                "state":{"anyOf":[{"type":"string"},{"type":"object"},{"type":"array"}]},
                "questions":{"type":"object","minProperties":1,"maxProperties":64,"propertyNames":{"pattern":"^[A-Za-z0-9_.-]{1,100}$"},"additionalProperties":{"oneOf":[
                    question("choice",Some(json!({"type":"object","minProperties":2,"maxProperties":255,"additionalProperties":{"type":"string"}}))),
                    question("score",Some(json!({"type":"array","minItems":2,"maxItems":10,"items":{"type":"string","minLength":1}}))),
                    question("noul",None)
                ]}}
            }}),
        }
    }

    async fn call(&self, arguments: Value, _sandbox: &Sandbox) -> ToolResult {
        let args = match Args::parse(arguments) {
            Ok(args) => args,
            Err(e) => return ToolResult::invalid_args(self.name(), e),
        };
        let result = tokio::time::timeout(TIMEOUT, self.evaluate(&args)).await;
        match result {
            Ok(Ok(value)) => {
                ToolResult::ok(value.to_string()).with_provenance(Provenance::Remote {
                    source: match args.backend {
                        Backend::Jev => "typesafe:jev",
                        Backend::Clef => "cloudflare:clef",
                    }
                    .into(),
                })
            }
            Ok(Err(error)) => ToolResult::error(error),
            Err(_) => {
                ToolResult::error("decision provider timed out; outcome and billing may be unknown")
            }
        }
    }
}

#[cfg(test)]
mod tests;
