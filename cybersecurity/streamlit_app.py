import streamlit as st
from datetime import datetime

st.set_page_config(page_title="CyberShield", page_icon="🛡️", layout="wide")
from pathlib import Path
import streamlit as st

CSS_PATH = Path(__file__).parent / "style.css"

if CSS_PATH.exists():
    css = CSS_PATH.read_text(encoding="utf-8")
    st.markdown(
        f"<style>{css}</style>",
        unsafe_allow_html=True
    )
else:
    st.error("style.css was not found.")

st.title("🛡️ CyberShield")
st.subheader("Cybersecurity Incident-Response Expert System")
st.write("Assess an incident and receive rule-based response recommendations.")

page = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Incident Assessment", "Incident History", "About Project"]
)

if "history" not in st.session_state:
    st.session_state.history = []

if page == "Dashboard":
    st.markdown(
        """
        <div style="
            background: linear-gradient(
                120deg, #0d1b2e, #0a2040, #102b49
            );
            border: 1px solid #1e3a5f;
            border-radius: 14px;
            padding: 36px;
            margin-bottom: 24px;
        ">
            <div style="
                color: #00d4ff;
                font-size: 12px;
                letter-spacing: 2px;
                font-weight: 700;
                margin-bottom: 18px;
            ">
                🛡️ KNOWLEDGE-BASED EXPERT SYSTEM
            </div>
            <h1 style="
                color: #ffffff;
                font-size: 34px;
                margin: 0 0 12px 0;
            ">
                CyberShield
            </h1>
            <h2 style="
                color: #00d4ff;
                font-size: 24px;
                margin: 0 0 14px 0;
            ">
                Cybersecurity Incident Response
            </h2>
            <p style="
                color: #b9cbe0;
                line-height: 1.7;
                max-width: 720px;
                margin-bottom: 0;
            ">
                An intelligent, rule-based expert system that guides
                users through cybersecurity incident identification
                and response with evidence-based recommendations.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader("Security Dashboard")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric("Incident Types", "6")

    with c2:
        st.metric("Response Rules", "25+")

    with c3:
        st.metric("Severity Levels", "4")

    st.info(
        "Choose Incident Assessment from the sidebar to begin."
    )

elif page == "Incident Assessment":
    st.header("Incident Assessment")

    with st.form("incident_form"):
        incident = st.selectbox(
            "Incident type",
            ["Phishing", "Malware", "Suspicious Login",
             "Data Breach", "Ransomware", "Other"]
        )
        severity = st.selectbox(
            "Severity", ["Low", "Medium", "High", "Critical"]
        )
        affected = st.text_input("Affected device or system")
        description = st.text_area("Describe what happened")
        submitted = st.form_submit_button("Assess Incident")

    if submitted:
        if not description.strip():
            st.warning("Please describe the incident.")
        else:
            actions = {
                "Phishing": [
                    "Do not click links or open attachments.",
                    "Report the message to your security team.",
                    "If you entered credentials, change them from a trusted device."
                ],
                "Malware": [
                    "Isolate the affected device from the network if safe.",
                    "Contact your IT/security team.",
                    "Preserve evidence and use approved security scans."
                ],
                "Suspicious Login": [
                    "Change your password from a trusted device.",
                    "Enable multifactor authentication.",
                    "Review account sessions and revoke unknown ones."
                ],
                "Data Breach": [
                    "Notify your security and privacy teams immediately.",
                    "Restrict affected access where authorized.",
                    "Preserve logs and follow your incident-response plan."
                ],
                "Ransomware": [
                    "Isolate affected devices if safe to do so.",
                    "Contact your incident-response team immediately.",
                    "Preserve evidence and do not attempt unapproved recovery."
                ],
                "Other": [
                    "Record the incident time and affected systems.",
                    "Report the incident to your security team.",
                    "Preserve relevant logs and evidence."
                ]
            }

            record = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "type": incident,
                "severity": severity,
                "affected": affected or "Not specified",
                "description": description
            }
            st.session_state.history.append(record)

            st.subheader("Assessment Results")
            st.write("**Incident:**", incident)
            st.write("**Severity:**", severity)
            st.write("**Affected system:**", affected or "Not specified")

            for action in actions[incident]:
                st.markdown(f"- {action}")

            if severity in ["High", "Critical"]:
                st.error("Escalate urgently to your security team.")
            else:
                st.info("Monitor the situation and follow your organization's security procedures.")

            st.caption("Preliminary rule-based guidance, not a substitute for professional incident response.")

elif page == "Incident History":
    st.header("Incident History")
    if st.session_state.history:
        st.dataframe(st.session_state.history, use_container_width=True)
    else:
        st.info("No incidents assessed in this session yet.")

elif page == "About Project":
    st.header("About CyberShield")
    st.write(
        "An educational rule-based expert system that uses incident "
        "categories and predefined rules to suggest initial response actions."
    )
