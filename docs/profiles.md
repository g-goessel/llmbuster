# Target profiles

A target profile tells `llmbuster` how to talk to an LLM endpoint. Profiles are
YAML files selected by their `kind` field. There are four kinds:

| Kind         | When to use                                                            |
| ------------ | ---------------------------------------------------------------------- |
| `openrouter` | Quickest path for OpenRouter. Just set `model:`; auth + body are built in. |
| `profile`    | Declarative HTTP against any OpenAI-compatible (or custom) endpoint.   |
| `plugin`     | You need Python logic (custom auth, non-HTTP transport). Loaded via `importlib`. |
| `command`    | Talk to a local subprocess over a JSON-line stdio protocol.            |

Run `uv run llmbuster targets init ./my-target.yaml` for a fully-commented
template covering every field, or `uv run llmbuster targets list` to see the
bundled profiles.

## Minimal `openrouter` profile

```yaml
kind: openrouter
name: "OpenRouter (free model)"
model: "openai/gpt-oss-20b:free"
```

The OpenRouter key is read from the `OPENROUTER_API_KEY` environment variable.
The built-in adapter streams responses over SSE (`"stream": true`) and sends
`"reasoning": {"exclude": true}` to hide reasoning/thinking tokens from the
response; detectors only evaluate the accumulated `choices[0].delta.content`
tokens, so reasoning data is never used for detection.

## Minimal `profile` (declarative HTTP)

```yaml
kind: profile
name: "My LLM"

request:
  method: POST
  url: "https://example.test/v1/chat/completions"
  headers:
    Content-Type: "application/json"
    Authorization: "Bearer ${env:MY_API_KEY}"
  body: |
    {"model": "my-model", "messages": ${messages_json}}

response:
  type: json            # json | sse | text
  reply_path: "$.choices[0].message.content"

session:
  mode: stateless       # stateless | server_managed | client_history
```

## Interpolation placeholders

The `request.body`, `request.url`, and `request.headers` values are run through
an interpolation engine. Supported placeholders:

| Placeholder              | Resolves to                                                |
| ------------------------ | --------------------------------------------------------- |
| `${env:VAR}`             | Environment variable `VAR`. **Secrets enter only here.** |
| `${uuid}`                | A fresh UUID4.                                            |
| `${timestamp}`           | Current UTC ISO-8601 timestamp.                           |
| `${messages_json}`       | The chat history serialized as JSON.                     |
| `${last_user_message}`   | The content of the last user message.                    |
| `${capture.<name>}`      | A value captured from a previous response.               |

Unknown placeholders raise a clear error; `${env:MISSING}` raises a clear error
when the variable is unset.

## Response transports

The `response.type` field controls how the reply is extracted from the HTTP
response. Streaming (`sse`) is required to capture TTFT/TPS — see
[Metrics](metrics.md).

| `type` | Behavior                                                        |
| ------ | --------------------------------------------------------------- |
| `json` | Parse JSON body; extract reply via JSONPath (`reply_path`).    |
| `sse`  | Stream token deltas; enables TTFT/TPS; concatenate deltas.    |
| `text` | Use the raw response body verbatim.                            |

## Session modes

The `session.mode` field controls how conversation state is carried across
attempts within a run (notably for escalation chains).

| Mode              | Behavior                                                          |
| ----------------- | ----------------------------------------------------------------- |
| `stateless`       | Each request is independent; no session state is sent.           |
| `server_managed`  | Capture a session id from the response and resend it on the next request. Escalation chains stay within the same session scope. |
| `client_history`  | Resend the full chat history with every request.                 |

## Next steps

- Author a pack to fire at your target — see [Payload packs](payloads.md).
- Run a scan with [CLI reference](cli.md).
