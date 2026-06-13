from __future__ import annotations

from dataclasses import dataclass

import httpx

from opswitness.incidents.models import IncidentBrief


@dataclass(frozen=True)
class SlackNotifier:
    webhook_url: str
    console_url: str = "http://127.0.0.1:3000"

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    async def send_incident(self, incident: IncidentBrief) -> tuple[str, str]:
        if not self.configured:
            return "not_configured", "SLACK_WEBHOOK_URL is unset"
        payload = self._payload(incident)
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(self.webhook_url, json=payload)
            response.raise_for_status()
            return "sent", response.text[:300]
        except httpx.HTTPError as exc:
            return "failed", str(exc)

    def _payload(self, incident: IncidentBrief) -> dict:
        evidence = ", ".join(f"`{node_id}`" for node_id in incident.evidence_node_ids[:5])
        return {
            "text": f"{incident.severity.upper()}: {incident.title}",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{incident.severity.upper()}: {incident.title}"},
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Probable cause*\n{incident.probable_cause}\n\n"
                            f"*Confidence:* {incident.confidence}%  |  "
                            f"*Error increase:* {incident.error_multiplier}x"
                        ),
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Affected services*\n{', '.join(incident.affected_services) or 'Unknown'}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Affected regions*\n{', '.join(incident.affected_regions) or 'Unknown'}",
                        },
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Evidence nodes*\n{evidence}\n\n*Proposed action*\n{incident.proposed_action}",
                    },
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Open evidence graph"},
                            "url": f"{self.console_url}?run={incident.run_id}",
                        }
                    ],
                },
            ],
        }
