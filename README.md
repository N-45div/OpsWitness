# OpsWitness

OpsWitness is an evidence-first incident investigation layer for AI agents that
use Splunk through MCP.

It sits between an MCP-capable agent and Splunk, records the real tool exchange,
reconstructs the investigation as a causal graph, detects unsafe paths, and
keeps remediation behind a human approval decision.

## The Problem

AI agents can investigate operational incidents quickly, but their conclusions
are difficult to trust when teams cannot answer:

- Which prompt, context, and tool metadata influenced the investigation?
- Which Splunk queries did the agent generate and execute?
- Did untrusted context influence a privileged or overly broad search?
- What evidence supports the proposed remediation?
- Was the final action reviewed by a human?

Traditional traces show a sequence of events. OpsWitness reconstructs the
causal path behind the agent's decisions and requires incident conclusions to
cite evidence nodes that actually exist in the recorded run.

## How OpsWitness Works

```text
MCP-capable AI agent
        |
        v
OpsWitness MCP proxy
        |
        +--> Splunk MCP Server --> Splunk data
        |
        +--> Splunk HEC evidence index
        |
        +--> Causal graph and policy analysis
        |
        +--> Incident Room, Slack brief, human approval
```

1. The agent connects to the OpsWitness MCP proxy.
2. OpsWitness discovers the live tools exposed by Splunk MCP Server.
3. Real MCP requests and responses are normalized into evidence events.
4. Evidence is written to Splunk through HEC and persisted locally.
5. OpsWitness reconstructs the run as a causal graph and evaluates risky paths.
6. Incident conclusions must cite graph evidence before OpsWitness accepts them.
7. Remediation proposals remain pending until a human approves or rejects them.

See [architecture_diagram.md](architecture_diagram.md) for the complete component and data flow.

## How Splunk Is Used

OpsWitness uses Splunk as the operational data source and independent evidence
system:

- **MCP Server for Splunk Platform** exposes live Splunk tools to AI agents.
- **HTTP Event Collector** stores agent actions, searches, incidents, and
  approval decisions using `sourcetype=opswitness:event`.
- **Indexer acknowledgement** can confirm that evidence was indexed before an
  action proceeds.
- **Splunk Search** independently verifies the evidence shown by OpsWitness.
- **Native SPL anomaly investigation** detects abnormal error changes without
  requiring MLTK or hosted models.
- **Splunk dashboard** provides an independent view of MCP calls, risky
  searches, incidents, and approvals.

The Splunk dashboard is intentionally separate from the OpsWitness UI.
OpsWitness is the investigation and governance surface; Splunk remains the
independent verification surface.

## Features

- Transparent MCP proxy for real Splunk tool calls
- Capability-aware Splunk MCP preflight
- Fail-closed HEC evidence capture
- Optional HEC indexer acknowledgement
- Causal context graph reconstruction
- Detection for prompt injection, poisoned tool metadata, broad searches,
  sensitive-index access, raw exports, and long query windows
- Portable Splunk-native anomaly investigation
- Evidence-cited deployment incident briefs
- Safe SPL query rewriting
- Slack incident notifications
- Human remediation approval workflow
- One-click live incident drill across HEC, MCP, native SPL, Slack, and approval
- Interactive Next.js evidence graph and timeline
- Importable native Splunk dashboard

## Technology

- Python 3.11
- FastAPI and Pydantic
- NetworkX and optional Kuzu graph storage
- Next.js, React, and Cytoscape.js
- Splunk HEC and MCP Server for Splunk Platform
- Slack incoming webhooks

## Requirements

- Python 3.11+
- Node.js 20+
- A Splunk instance with HTTP Event Collector
- MCP Server for Splunk Platform and an encrypted MCP token
- Optional Slack incoming webhook

## Installation

```bash
git clone https://github.com/N-45div/OpsWitness.git
cd OpsWitness

python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

cd frontend
npm install
cd ..
```

## Configuration

Copy the example environment file and add your credentials:

```bash
cp .env.example .env
```

Required for the real evidence path:

```bash
SPLUNK_HEC_URL=https://<stack>.splunkcloud.com:8088/services/collector/event
SPLUNK_HEC_TOKEN=<hec-token>
SPLUNK_INDEX=opswitness
SPLUNK_REQUIRE_HEC=true

SPLUNK_MCP_URL=https://<stack>.splunkcloud.com/en-US/splunkd/__raw/services/mcp
SPLUNK_MCP_BEARER_TOKEN=<encrypted-mcp-token>
```

Useful options:

```bash
SPLUNK_HEC_ACK_MODE=auto
SPLUNK_HEC_ACK_TIMEOUT_SECONDS=10
SLACK_WEBHOOK_URL=
OPSWITNESS_CONSOLE_URL=http://127.0.0.1:3000
```

`SPLUNK_HEC_ACK_MODE` supports:

- `auto`: confirm indexing when available and otherwise report HEC acceptance.
- `required`: fail closed unless Splunk confirms indexing.
- `disabled`: require only HEC acceptance.

Never commit Splunk or Slack credentials.

## Run Locally

Start the API on port `8000`:

```bash
make api
```

Start the frontend on port `3000`:

```bash
make frontend
```

Open `http://127.0.0.1:3000`.

Click **Run live incident drill** to execute the configured integrations end to
end. OpsWitness fails visibly at the exact unavailable stage and never replaces
it with sample data. A successful run loads its evidence graph and leaves the
proposed remediation pending for a human approval or rejection.

The console includes three live investigation scenarios:

- Checkout deployment regression using error-spike SPL
- Credential-stuffing attack using authentication-failure SPL
- Order queue saturation using queue-depth and p95-latency SPL

## Connect An MCP Client

Configure an MCP-capable AI client to connect through OpsWitness:

```json
{
  "mcpServers": {
    "opswitness-splunk": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://127.0.0.1:8000/mcp",
        "--header",
        "x-opswitness-agent-id: ai-incident-investigator",
        "--header",
        "x-opswitness-run-id: incident-room-live"
      ]
    }
  }
}
```

The encrypted Splunk MCP token stays in the OpsWitness backend and is not
exposed to the AI client.

## Splunk Workflows

Run capability-aware MCP preflight:

```bash
curl -sS -X POST http://127.0.0.1:8000/splunk/mcp/preflight \
  -H 'content-type: application/json' \
  -d '{"run_id":"preflight-demo"}'
```

Generate or execute portable anomaly-detection SPL:

```bash
curl -sS -X POST http://127.0.0.1:8000/splunk/anomaly-investigation \
  -H 'content-type: application/json' \
  -d '{"service":"checkout-api","index":"main","execute":true}'
```

Import [`splunk/opswitness_dashboard.xml`](splunk/opswitness_dashboard.xml) as
a Classic Splunk dashboard.

Useful verification SPL:

```spl
index=opswitness sourcetype=opswitness:event
| table _time event_type run_id agent_id node_id parent_node_id source_trust risk_tags
```

```spl
index=opswitness sourcetype=opswitness:event event_type="splunk.search.generated"
| table _time run_id payload.query risk_tags
```

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | API and local evidence-store health |
| `POST` | `/events` | Ingest normalized agent evidence |
| `POST` | `/mcp` | Transparent MCP proxy |
| `POST` | `/mcp/trace` | Record mirrored MCP traffic |
| `POST` | `/mcp/proxy` | Wrapped MCP proxy request |
| `GET` | `/runs` | List recorded runs |
| `GET` | `/runs/{run_id}` | Read a causal evidence graph |
| `GET` | `/runs/{run_id}/spl` | Generate verification SPL |
| `GET` | `/splunk/status` | Inspect configured Splunk capabilities |
| `POST` | `/splunk/mcp/preflight` | Discover and safely call MCP metadata tools |
| `POST` | `/splunk/anomaly-investigation` | Generate or execute native anomaly SPL |
| `POST` | `/drills/live-incident` | Run the fail-closed live incident pipeline |
| `POST` | `/drills/live-incident/jobs` | Start a non-blocking live drill job |
| `GET` | `/drills/live-incident/jobs/{job_id}` | Poll live drill progress and result |
| `POST` | `/integrations/deployments` | Record deployment context |
| `POST` | `/incidents` | Create an evidence-cited incident |
| `POST` | `/incidents/{incident_id}/approval` | Approve or reject remediation |

Interactive API documentation is available at `http://127.0.0.1:8000/docs`.

## Testing

Run the complete validation suite:

```bash
make check
```

Or run components individually:

```bash
.venv/bin/python -m ruff check src tests
.venv/bin/python -m pytest tests
cd frontend && npm run build
```

The test fixtures include safe and unsafe agent traces and are used only by the
automated policy tests.

## Security

- OpsWitness fails closed when HEC is required but unavailable.
- Incident conclusions are rejected when cited evidence nodes do not exist.
- MCP capability preflight calls only advertised tools whose required arguments
  are available.
- Optional Splunk features are never represented as active unless the connected
  instance exposes them.
- Secrets are loaded from environment variables and excluded from the
  repository.

## License

[MIT](LICENSE)
