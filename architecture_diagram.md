# OpsWitness Architecture

## System Context

```mermaid
flowchart LR
  subgraph External["External Systems"]
    Agent["MCP-capable AI Agent"]
    CICD["CI/CD System"]
    Human["Incident Commander"]
    Slack["Slack"]
  end

  subgraph OpsWitness["OpsWitness"]
    API["FastAPI API<br/>:8000"]
    Proxy["Transparent MCP Proxy<br/>POST /mcp"]
    Preflight["Capability-aware Preflight<br/>POST /splunk/mcp/preflight"]
    Anomaly["Native SPL Anomaly Investigation<br/>POST /splunk/anomaly-investigation"]
    Normalize["Pydantic Event Normalizer"]
    Policy["NetworkX Policy Analyzer"]
    Explain["Evidence Explainer"]
    Incident["Incident and Approval Service"]
    Verify["Approved Detection Verifier"]
    Hosted["Splunk-hosted Analytics"]
    KVPolicy["KV Policy Resolver"]
    SOARAdapter["SOAR Approval Adapter"]
    UI["Next.js Incident Room<br/>:3000"]
  end

  subgraph Storage["OpsWitness Local State"]
    Events[("JSON Event Store")]
    Graphs[("JSON Graph Store")]
    Incidents[("JSON Incident Store")]
    Kuzu[("Optional Kuzu Graph Store")]
  end

  subgraph Splunk["Splunk Platform"]
    MCP["MCP Server for Splunk Platform"]
    Data[("Operational Data")]
    HEC["HTTP Event Collector"]
    Index[("opswitness:event Evidence Index")]
    Dashboard["OpsWitness Splunk Dashboard"]
    Saved["Approved Saved Searches"]
    KV[("OpsWitness KV Store")]
    Models["Native Analytics / MLTK Models"]
    SOAR["Splunk SOAR"]
  end

  Agent --> Proxy
  Proxy --> MCP
  MCP --> Data
  MCP --> Proxy

  Agent -. mirrored traffic .-> API
  CICD --> API
  Human --> UI
  UI --> API

  API --> Preflight
  API --> Anomaly
  API --> Hosted
  API --> Verify
  API --> KVPolicy
  Preflight --> MCP
  Anomaly --> MCP
  Hosted --> MCP
  Verify --> MCP
  KVPolicy --> MCP
  MCP --> Saved
  MCP --> KV
  MCP --> Models

  Proxy --> Normalize
  Preflight --> Normalize
  Anomaly --> Normalize
  API --> Normalize
  Normalize --> HEC
  HEC --> Index

  Normalize --> Events
  Events --> Policy
  Policy --> Graphs
  Policy -. optional adapter .-> Kuzu
  Graphs --> Explain
  Explain --> Incident
  Incident --> Incidents
  Incident --> Slack
  Incident --> SOARAdapter
  SOARAdapter --> SOAR
  Incident --> UI

  Index --> Dashboard
```

## MCP Investigation And Evidence Capture

```mermaid
sequenceDiagram
  autonumber
  participant Agent as AI Agent
  participant Proxy as OpsWitness MCP Proxy
  participant MCP as Splunk MCP Server
  participant HEC as Splunk HEC
  participant Store as Event and Graph Stores
  participant UI as OpsWitness Incident Room

  Agent->>Proxy: initialize
  Proxy->>MCP: initialize with encrypted MCP token
  MCP-->>Proxy: protocol version and session headers
  Proxy->>HEC: record MCP initialization evidence
  Proxy-->>Agent: initialization response

  Agent->>Proxy: tools/list
  Proxy->>MCP: tools/list
  MCP-->>Proxy: advertised Splunk tools
  Proxy->>HEC: record mcp.tool.available events
  Proxy->>Store: persist and rebuild run graph
  Proxy-->>Agent: live tool inventory

  Agent->>Proxy: tools/call splunk_run_query
  Proxy->>MCP: forward scoped SPL query
  MCP-->>Proxy: real Splunk query result
  Proxy->>HEC: record tool call, generated SPL, and result
  Proxy->>Store: persist events and evaluate risky paths
  Proxy-->>Agent: query result

  UI->>Store: GET /runs/{run_id}
  Store-->>UI: causal evidence graph and policy findings
```

## Capability-aware Splunk Execution

```mermaid
flowchart TD
  Start["POST /splunk/mcp/preflight"] --> Configured{"SPLUNK_MCP_URL configured?"}
  Configured -- No --> Unavailable["Return unavailable<br/>Do not claim capability"]
  Configured -- Yes --> Init["MCP initialize"]
  Init --> List["MCP tools/list"]
  List --> Inventory["Build live tool inventory"]

  Inventory --> Candidate{"For each preflight tool"}
  Candidate --> Advertised{"Tool advertised?"}
  Advertised -- No --> Missing["Record unavailable tool"]
  Advertised -- Yes --> Required{"Schema requires contextual arguments?"}
  Required -- Yes --> Skip["Record skipped contextual tool"]
  Required -- No --> Execute["Execute metadata tool"]

  Missing --> Result
  Skip --> Result
  Execute --> Result["Return ready or partial status"]

  Result --> QueryCheck{"splunk_run_query advertised?"}
  QueryCheck -- No --> QueryOnly["Generate portable anomaly SPL only"]
  QueryCheck -- Yes --> QueryExecute["Execute portable anomaly SPL through MCP"]

  QueryOnly --> Evidence["Persist truthful capability result"]
  QueryExecute --> Evidence
```

## Evidence Persistence And HEC Acknowledgement

```mermaid
stateDiagram-v2
  [*] --> Normalize: MCP, deployment, incident, or approval event
  Normalize --> RequireHEC

  state RequireHEC <<choice>>
  RequireHEC --> Rejected: HEC required but not configured
  RequireHEC --> SendHEC: HEC configured
  RequireHEC --> PersistLocal: HEC not required for local testing

  SendHEC --> Accepted: HEC accepts event
  Accepted --> AckDecision

  state AckDecision <<choice>>
  AckDecision --> PersistLocal: acknowledgement disabled or unavailable
  AckDecision --> PollAck: ackId returned
  AckDecision --> Rejected: acknowledgement required but no ackId returned

  PollAck --> Indexed: Splunk confirms every ackId
  PollAck --> AcceptedUnconfirmed: timeout in auto mode
  PollAck --> Rejected: timeout in required mode

  Indexed --> PersistLocal
  AcceptedUnconfirmed --> PersistLocal
  PersistLocal --> RebuildGraph
  RebuildGraph --> EvaluatePolicy
  EvaluatePolicy --> [*]
  Rejected --> [*]
```

## Causal Evidence Graph

```mermaid
flowchart LR
  Run["Run"] -->|STARTED_WITH| Prompt["Prompt"]
  Prompt -->|RETRIEVED| Context["Context Chunk"]
  Context -->|EXPOSED_TOOL| Tool["MCP Tool Metadata"]
  Tool -->|SELECTED_TOOL| Decision["Tool Decision"]
  Decision -->|CALLED| Call["Tool Call"]
  Call -->|GENERATED_SEARCH| Search["Splunk Search"]
  Search -->|EXECUTED_SEARCH| Result["Splunk Result"]
  Result -->|TRIGGERED_POLICY| Policy["Policy Decision"]
  Policy -->|REQUESTED_APPROVAL| Approval["Approval Request"]
  Approval -->|APPROVED or REJECTED| ApprovalDecision["Approval Decision"]

  Deployment["Deployment"] -->|TRIGGERED_INCIDENT| Incident["Incident"]
  Incident -->|PROPOSED_REMEDIATION| Remediation["Remediation Proposal"]
  Remediation -->|REQUESTED_APPROVAL| Approval
  Incident -->|NOTIFIED| Notification["Slack Notification"]

  Context -. prompt injection .-> Risk["Risk Path"]
  Tool -. poisoned metadata .-> Risk
  Search -. broad search or raw export .-> Risk
  Risk --> Policy
```

## Incident And Remediation Lifecycle

```mermaid
sequenceDiagram
  autonumber
  participant CICD as CI/CD
  participant API as OpsWitness API
  participant Graph as Evidence Graph
  participant Splunk as Splunk HEC and Search
  participant Policy as Splunk KV and Saved Searches
  participant SOAR as Splunk SOAR
  participant Slack as Slack
  participant Human as Incident Commander

  CICD->>API: POST /integrations/deployments
  API->>Splunk: index deployment.recorded evidence
  API->>Graph: add Deployment node

  API->>Splunk: investigate operational evidence through MCP
  Splunk-->>API: scoped query results
  API->>Splunk: run hosted anomaly analytics
  API->>Policy: execute approved saved search and resolve KV policy
  Policy-->>API: verification and allowed response
  API->>Graph: add ToolCall, SplunkSearch, and SplunkResult nodes

  API->>Graph: validate every cited evidence_node_id
  alt Any citation is missing
    API-->>CICD: reject incident conclusion
  else All citations exist
    API->>API: calculate error multiplier, severity, and confidence
    API->>API: rewrite unsafe SPL into a scoped safe query
    API->>Graph: add Incident, RemediationProposal, and Approval nodes
    API->>Splunk: index incident and approval-request evidence
    opt Slack webhook configured
      API->>Slack: send evidence-cited incident brief
      API->>Graph: add Notification node only after successful send
    end
  end

  Human->>API: POST /incidents/{incident_id}/approval
  alt Approved
    API->>Graph: add APPROVED decision
    API->>Splunk: index human.approval.approved
    API->>SOAR: run mapped bounded playbook
    SOAR-->>API: execution result
  else Rejected
    API->>Graph: add REJECTED decision
    API->>Splunk: index human.approval.rejected
  end
```

## Verification Surfaces

```mermaid
flowchart LR
  Event["Agent or Incident Event"] --> OpsWitness["OpsWitness Incident Room"]
  Event --> Splunk["Splunk Evidence Index"]

  OpsWitness --> Graph["Causal graph, findings, and approvals"]
  Splunk --> Dashboard["Independent Splunk dashboard"]
  Splunk --> Search["Verification SPL"]

  Graph --> Compare{"Evidence agrees?"}
  Dashboard --> Compare
  Search --> Compare

  Compare -- Yes --> Proven["Investigation is independently verifiable"]
  Compare -- No --> Investigate["Evidence mismatch requires investigation"]
```
