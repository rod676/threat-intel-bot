import streamlit as st
from fetcher import get_recent_cves, get_cve_by_id
from analyzer import analyze_cve, analyze_batch

st.set_page_config(
    page_title="Threat Intel Bot",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Threat Intel Bot")
st.caption("Real-time CVE monitoring powered by NIST NVD + GPT-4o")
st.divider()

tab1, tab2 = st.tabs(["📡 Live CVE Feed", "🔎 Search CVE by ID"])

# Tab 1 — Live Feed
with tab1:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        hours = st.slider(
            "Time range (hours)",
            min_value=6,
            max_value=72,
            value=24,
            step=6
        )
    
    with col2:
        severity_filter = st.selectbox(
            "Min severity",
            ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
    
    if st.button("🔄 Fetch Latest CVEs", type="primary"):
        with st.spinner("Fetching from NIST NVD database..."):
            cves = get_recent_cves(hours=hours, max_results=20)
        
        if not cves:
            st.warning("No CVEs found for this time range. Try extending the window.")
        else:
            # Filtre par sévérité
            if severity_filter != "ALL":
                cves = [c for c in cves if c["severity"] == severity_filter]
            
            st.success(f"Found {len(cves)} CVEs — analyzing top 5 critical ones...")
            
            # Analyse GPT des 5 plus critiques
            with st.spinner("🧠 AI analysis in progress..."):
                analyzed = analyze_batch(cves, max_analyze=5)
            
            # Affichage
            for cve in analyzed:
                severity = cve.get("severity", "UNKNOWN")
                score = cve.get("score", "N/A")
                
                color_map = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢",
                    "UNKNOWN": "⚪"
                }
                emoji = color_map.get(severity, "⚪")
                
                with st.expander(
                    f"{emoji} {cve['id']} — {cve.get('title', 'Loading...')} "
                    f"| Score: {score}/10 | {severity}"
                ):
                    if "executive_summary" in cve:
                        st.info(cve["executive_summary"])
                    
                    col1, col2, col3 = st.columns(3)
                    col1.metric("CVSS Score", f"{score}/10")
                    col2.metric("Severity", severity)
                    col3.metric(
                        "Urgency",
                        cve.get("urgency", "ANALYZING...")
                    )
                    
                    if "affected_systems" in cve:
                        st.write(f"**Affected Systems:** {cve['affected_systems']}")
                    
                    if "impact" in cve:
                        st.write(f"**Impact:** {cve['impact']}")
                    
                    if "recommended_action" in cve:
                        st.success(
                            f"**Recommended Action:** {cve['recommended_action']}"
                        )
                    
                    if cve.get("references"):
                        st.write("**References:**")
                        for ref in cve["references"]:
                            st.write(f"• {ref}")
                    
                    st.caption(f"Published: {cve['published']}")

# Tab 2 — Search by ID
with tab2:
    cve_id_input = st.text_input(
        "Enter CVE ID",
        placeholder="CVE-2024-12345"
    )
    
    if st.button("🔎 Analyze", type="primary"):
        if cve_id_input:
            with st.spinner(f"Fetching {cve_id_input}..."):
                cve_data = get_cve_by_id(cve_id_input)
            
            if "error" in cve_data:
                st.error(cve_data["error"])
            else:
                with st.spinner("🧠 AI analysis..."):
                    result = analyze_cve(cve_data)
                
                st.subheader(f"📋 {result['id']}")
                
                if "executive_summary" in result:
                    st.info(result["executive_summary"])
                
                if "recommended_action" in result:
                    st.success(f"**Action:** {result['recommended_action']}")
                
                with st.expander("Full Technical Details"):
                    st.json(result)
        else:
            st.warning("Please enter a CVE ID")

st.divider()
st.caption("Data source: NIST NVD · Built by Olade Roland Sagbo · Hamburg 🇩🇪")