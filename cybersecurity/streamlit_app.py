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
    st.header("Security Dashboard")
    c1, c2, c3 = st.columns(3)
    c1.metric("Incident Types", "6")
    c2.metric("Response Rules", "25+")
    c3.metric("Severity Levels", "4")
    st.info("Choose Incident Assessment from the sidebar to begin.")

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
