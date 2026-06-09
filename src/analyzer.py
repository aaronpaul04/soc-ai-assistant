"""
LLM-powered SOC alert analyzer using Gemini.
Takes raw alert + IOC enrichment, returns structured triage output.
"""

import os
import json
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY", ""))

MODEL_NAME = "gemini-2.5-flash"

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst with 10 years of experience.
You triage security alerts for a mid-sized company. You explain things in clear English so a junior analyst can follow.
You are calm, accurate, and never overstate severity.

Given a raw security alert plus threat intelligence enrichment on the IOCs found in it, produce a JSON object with these fields:

{
  "summary": "1-2 sentence plain-English explanation of what happened",
  "severity": "info | low | medium | high | critical",
  "severity_reasoning": "1 sentence on why you picked that severity",
  "attack_techniques": ["list of relevant MITRE ATT&CK techniques like T1110 (Brute Force) - max 4"],
  "key_findings": ["bullet list of the most important specific facts - max 5"],
  "triage_steps": ["ordered list of concrete next actions the analyst should take - max 6"],
  "false_positive_check": "1-2 sentences on what could make this a false positive"
}

Output ONLY valid JSON, no markdown fences, no preamble. Be specific. Reference actual IPs, hashes, hostnames from the alert.
"""


def analyze_alert(raw_alert: str, enriched_iocs: dict) -> dict:
    """Send alert + enrichment to Gemini and parse the JSON response."""
    if not os.getenv("GEMINI_API_KEY"):
        return {"error": "GEMINI_API_KEY not configured"}

    model = genai.GenerativeModel(
        model_name=MODEL_NAME,
        system_instruction=SYSTEM_PROMPT,
    )

    user_msg = f"""RAW ALERT:
{raw_alert}

IOC ENRICHMENT DATA:
{json.dumps(enriched_iocs, indent=2, default=str)}

Produce the JSON analysis now."""

    try:
        response = model.generate_content(
            user_msg,
            generation_config={
                "temperature": 0.2,
                "response_mime_type": "application/json",
            },
        )
        return json.loads(response.text)
    except json.JSONDecodeError as e:
        return {"error": f"LLM returned non-JSON: {e}", "raw": response.text}
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    sample_alert = """
    Alert: Multiple failed SSH login attempts followed by successful authentication
    Host: prod-web-03.internal
    Time: 2026-06-09T02:14:33Z
    Source IP: 185.220.101.42
    Target user: root
    Failed attempts: 1,247 over 6 minutes
    Successful login: 2026-06-09T02:20:12Z
    """

    # Stub enrichment matching what we'd get from real APIs
    sample_enrichment = {
        "ipv4": [{
            "ioc": "185.220.101.42",
            "virustotal": {"malicious": 15, "reputation": -18, "tags": ["tor"]},
            "abuseipdb": {"abuse_confidence": 100, "is_tor": True, "total_reports": 109},
        }]
    }

    print("Calling Gemini for analysis...\n")
    result = analyze_alert(sample_alert, sample_enrichment)
    print(json.dumps(result, indent=2))