import streamlit as st
import streamlit.components.v1 as components
from pathlib import Path

st.set_page_config(
    page_title="Cybersecurity Expert System",
    layout="wide"
)

st.title("Cybersecurity Expert System")

project_folder = Path(__file__).parent
html_file = project_folder / "index.html"

if html_file.exists():
    html_code = html_file.read_text(encoding="utf-8")
    components.html(html_code, height=900, scrolling=True)
else:
    st.error("index.html was not found.")
