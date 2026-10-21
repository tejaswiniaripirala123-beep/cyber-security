import streamlit as st
import streamlit.components.v1 as components
from pathlib import Path

st.set_page_config(
    page_title="Cybersecurity Expert System",
    layout="wide"
)

st.title("Cybersecurity Expert System")

base = Path(__file__).parent
html_path = base / "index.html"

if html_path.exists():
    html = html_path.read_text(encoding="utf-8")

    for folder in ["css", "js"]:
        html = html.replace(
            f'href="{folder}/',
            f'href="app/{folder}/'
        ).replace(
            f'src="{folder}/',
            f'src="app/{folder}/'
        )

    components.html(html, height=1000, scrolling=True)
else:
    st.error("index.html was not found.")
