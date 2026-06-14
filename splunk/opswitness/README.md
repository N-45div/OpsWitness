# OpsWitness Splunk App

This package installs the Splunk-managed assets used by OpsWitness:

- Approved saved searches for the three live drill scenarios
- KV Store collections for service policy, response playbooks, and model feedback
- Lookup definitions for reading those collections through SPL
- The OpsWitness evidence operations dashboard

Install the `splunk/opswitness` directory as a private Splunk app, then seed the
KV Store collections by running the `OpsWitness - Seed Service Policy` and
`OpsWitness - Seed Response Playbooks` saved searches. Replace the included
seed records with policy appropriate for the target environment.
OpsWitness discovers these assets through Splunk MCP and fails visibly when they
are unavailable.
