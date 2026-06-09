"""
SOC AI Assistant - paste a security alert, get an LLM-powered triage analysis.
"""

import os
import sys
import json
import time
import streamlit as st

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

from extractor import extract_iocs
from enrichment import (
    enrich_ip_vt, enrich_ip_abuseipdb,
    enrich_hash_vt, enrich_domain_vt, enrich_url_vt,
)
from analyzer import analyze_alert

SAMPLE_ALERTS = {
    "SSH brute force from Tor": """Alert: Multiple failed SSH login attempts followed by successful authentication
Host: prod-web-03.internal
Time: 2026-06-09T02:14:33Z
Source IP: 185.220.101.42
Target user: root
Failed attempts: 1,247 over 6 minutes
Successful login: 2026-06-09T02:20:12Z""",

    "Suspicious PowerShell + C2": """Alert: Suspicious PowerShell execution with outbound network connection
Host: FINANCE-WS-12
User: jdoe
Process: powershell.exe -nop -w hidden -enc <base64>
Decoded payload contacts: http://malicious-domain.tk/beacon.php
Outbound IP: 91.219.236.222
File dropped (SHA256): a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456""",

    "Phishing email with attachment": """Alert: Phishing email detected by mail security gateway
From: it-support@micros0ft-secure.com
To: alice.smith@company.com
Subject: URGENT: Your password expires today - verify immediately
Attachment: invoice_4521.docm (SHA256: 5d41402abc4b2a76b9719d911017c592)
Link in body: https://login-verify-account.tk/auth
Source IP: 192.42.116.20""",
}


def main():
    st.set_page_config(page_title="SOC AI Assistant", page_icon="🛡️", layout="wide")
    st.title("🛡️ SOC AI Assistant")
    st.caption("Paste a security alert, get an LLM-powered triage analysis with IOC enrichment.")

    # Sample picker
    sample_choice = st.selectbox(
        "Load a sample alert (or paste your own below):",
        ["-- Pick a sample --"] + list(SAMPLE_ALERTS.keys()),
    )
    if sample_choice in SAMPLE_ALERTS:
        st.session_state["alert_text"] = SAMPLE_ALERTS[sample_choice]

    alert_text = st.text_area(
        "Raw alert",
        value=st.session_state.get("alert_text", ""),
        height=200,
        placeholder="Paste the raw alert here...",
    )

    col1, col2 = st.columns([1, 3])
    with col1:
        enrich_enabled = st.checkbox("Enable threat intel (slower)", value=True)
    with col2:
        max_per_type = st.slider("Max IOCs per type to enrich", 1, 5, 3)

    if st.button("Analyze", type="primary", use_container_width=True):
        if not alert_text.strip():
            st.warning("Paste an alert first.")
            return

        # Step 1: extract
        with st.spinner("Extracting IOCs..."):
            iocs = extract_iocs(alert_text)

        st.subheader("Extracted IOCs")
        cols = st.columns(len(iocs))
        for col, (name, items) in zip(cols, iocs.items()):
            with col:
                st.markdown(f"**{name}** ({len(items)})")
                for it in items:
                    st.code(it, language=None)

        # Step 2: enrich
        enriched = {}
        if enrich_enabled and any(iocs.values()):
            st.subheader("Threat intel enrichment")
            progress = st.progress(0, text="Querying VirusTotal and AbuseIPDB...")
            total_calls = (
                len(iocs["ipv4"][:max_per_type])
                + len(iocs.get("md5", [])[:max_per_type])
                + len(iocs.get("sha256", [])[:max_per_type])
                + len(iocs.get("domain", [])[:max_per_type])
                + len(iocs.get("url", [])[:max_per_type])
            )
            done = 0

            enriched["ipv4"] = []
            for ip in iocs["ipv4"][:max_per_type]:
                enriched["ipv4"].append({
                    "ioc": ip,
                    "virustotal": enrich_ip_vt(ip),
                    "abuseipdb": enrich_ip_abuseipdb(ip),
                })
                done += 1
                progress.progress(done / max(total_calls, 1), text=f"Enriched {done}/{total_calls}")
                time.sleep(15)

            enriched["hashes"] = []
            for h in (iocs.get("md5", []) + iocs.get("sha256", []))[:max_per_type]:
                enriched["hashes"].append({"ioc": h, "virustotal": enrich_hash_vt(h)})
                done += 1
                progress.progress(done / max(total_calls, 1), text=f"Enriched {done}/{total_calls}")
                time.sleep(15)

            enriched["domains"] = []
            for d in iocs.get("domain", [])[:max_per_type]:
                enriched["domains"].append({"ioc": d, "virustotal": enrich_domain_vt(d)})
                done += 1
                progress.progress(done / max(total_calls, 1), text=f"Enriched {done}/{total_calls}")
                time.sleep(15)

            enriched["urls"] = []
            for u in iocs.get("url", [])[:max_per_type]:
                enriched["urls"].append({"ioc": u, "virustotal": enrich_url_vt(u)})
                done += 1
                progress.progress(done / max(total_calls, 1), text=f"Enriched {done}/{total_calls}")
                time.sleep(15)

            progress.empty()

            with st.expander("Raw enrichment data"):
                st.json(enriched)

        # Step 3: LLM analysis
        with st.spinner("Analyzing with Gemini..."):
            analysis = analyze_alert(alert_text, enriched)

        if "error" in analysis:
            st.error(f"LLM error: {analysis['error']}")
            return

        st.subheader("AI Analysis")

        # Severity badge
        severity = analysis.get("severity", "unknown").lower()
        sev_colors = {
            "critical": "red", "high": "red", "medium": "orange",
            "low": "blue", "info": "gray", "unknown": "gray",
        }
        st.markdown(f"### Severity: :{sev_colors.get(severity, 'gray')}[**{severity.upper()}**]")
        st.caption(analysis.get("severity_reasoning", ""))

        st.markdown("**Summary**")
        st.write(analysis.get("summary", ""))

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("**Key findings**")
            for f in analysis.get("key_findings", []):
                st.markdown(f"- {f}")
        with col_b:
            st.markdown("**Triage steps**")
            for i, s in enumerate(analysis.get("triage_steps", []), 1):
                st.markdown(f"{i}. {s}")

        st.markdown("**MITRE ATT&CK techniques**")
        for t in analysis.get("attack_techniques", []):
            st.markdown(f"- `{t}`")

        st.markdown("**False positive check**")
        st.info(analysis.get("false_positive_check", ""))

        with st.expander("Raw JSON output"):
            st.json(analysis)

    st.markdown("---")
    st.caption("Built with Python, Gemini, VirusTotal, AbuseIPDB, Streamlit. GitHub: [@aaronpaul04](https://github.com/aaronpaul04)")


if __name__ == "__main__":
    main()