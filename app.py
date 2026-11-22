
import streamlit as st
from detector import analyze_url

st.set_page_config(
    page_title="PHISHGUARD",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ PHISHGUARD")
st.subheader("Intelligent Phishing Detection")
st.caption("Defensive URL analysis and security awareness")

st.markdown("""
Analyze suspicious URLs using basic security indicators.
This tool does not guarantee that a website is safe.
""")

url = st.text_input(
    "Enter a URL to analyze",
    placeholder="https://example.com"
)

if st.button("Analyze URL", use_container_width=True):
    if not url.strip():
        st.warning("Please enter a URL first.")
    else:
        result = analyze_url(url)

        st.markdown("---")
        st.subheader("Analysis Results")

        st.metric("Risk Score", f'{result["score"]}/100')

        if result["risk"] == "High":
            st.error("High Risk")
        elif result["risk"] == "Medium":
            st.warning("Medium Risk")
        else:
            st.success("Low Risk")

        st.write("**Domain:**", result["host"])

        st.write("### Security Findings")

        for finding in result["findings"]:
            st.write("⚠️", finding)

        st.caption(
            "PHISHGUARD is an experimental tool. "
            "A low score does not guarantee website safety."
        )

st.markdown("---")
st.caption("PHISHGUARD | Open-source cybersecurity project")
