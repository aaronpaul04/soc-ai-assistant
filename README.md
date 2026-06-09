# SOC AI Assistant

**Live demo:** https://soc-ai-assistant.streamlit.app

An AI-powered tool that takes raw security alerts and produces a senior-SOC-analyst-grade triage in 30 seconds.

## What is this

You paste a raw security alert. The app:

- Extracts every IP, hash, domain, URL, and email in it
- Looks each one up on VirusTotal and AbuseIPDB
- Sends the alert plus enrichment data to Gemini for analysis
- Returns severity, MITRE ATT&CK techniques, key findings, triage steps, and a false positive check

Cuts the first pass of alert triage from 10 minutes to 30 seconds.

## How it works

Three modules, each one independently testable:

**extractor.py** - regex-based IOC extraction. Pulls IPs (filtering out private ranges that don't have threat intel), URLs, domains, MD5 / SHA1 / SHA256 hashes, and emails. Returns a deduplicated dictionary per type.

**enrichment.py** - threat intel lookups. Hits VirusTotal v3 for IPs, hashes, domains, and URLs. Hits AbuseIPDB for IPs to get the abuse confidence score and Tor/proxy flags. Respects free-tier rate limits.

**analyzer.py** - the LLM brain. Builds a prompt with the raw alert plus all the enrichment data, sends it to Gemini with a senior-analyst system prompt, and parses back a JSON object with severity, summary, MITRE techniques, key findings, triage steps, and false positive check.

**streamlit_app.py** - the UI. Sample alert dropdown, paste-your-own text box, live progress as the enrichment runs, color-coded severity badge, side-by-side findings and triage steps.

## Sample alerts included

The dropdown ships with three realistic alerts to test with:

- SSH brute force from a Tor exit node ending in a successful root login
- Encoded PowerShell beacon contacting an external C2 server
- Phishing email with a malicious DOCM attachment and credential-harvesting link

Pick one, click Analyze, watch the pipeline run end-to-end.

## Tech used

- Python 3.11+
- Streamlit for the web UI
- Google Gemini API as the LLM (free tier, no card)
- VirusTotal v3 API for file/IP/URL/domain reputation
- AbuseIPDB v2 API for IP reputation
- Hosted on Streamlit Community Cloud

## Repo structure

**src/**

- `extractor.py` IOC extraction
- `enrichment.py` VirusTotal and AbuseIPDB clients
- `analyzer.py` Gemini-powered alert analyzer

**app/**

- `streamlit_app.py` Web UI

**data/samples/** Example raw alerts

## Limitations

The free tier of VirusTotal caps at 4 requests per minute, so processing more than a few IOCs takes a noticeable wait. A paid key removes that. Severity ratings come from the LLM, not a trained classifier on real incident data, so they can be off in edge cases. The regex extractor catches the common 95% but misses defanged indicators like `hxxp://evil[.]com`.

## What I'd add next

A defanging pre-processor for obfuscated IOCs, a save-analysis button that writes results to SQLite for alert history, a Slack webhook so analyses post straight to a channel, and Sentinel integration to pull live alerts via Microsoft Graph instead of paste-and-go.
