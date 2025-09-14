import streamlit as st
import pandas as pd
from datetime import datetime
import os
import streamlit.components.v1 as components, html

# Configure page
st.set_page_config(
    page_title="SkyTrace - AI",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'login_data' not in st.session_state:
    st.session_state.login_data = None
if 'anomaly_results' not in st.session_state:
    st.session_state.anomaly_results = None
if 'risk_threshold' not in st.session_state:
    st.session_state.risk_threshold = 0.7

# --- HERO SECTION WITH VANTA GLOBE (Left-aligned title) ---
hero_section = """
<div id="vanta-hero" style="width: 150%; height: 300px; position: relative; border-radius: 12px; overflow: hidden;">
  <div style="position: absolute; z-index: 1; width: 100%; height: 100%; 
              display: flex; flex-direction: column; justify-content: center; 
              align-items: flex-start; padding-left: 40px; color: white;">
    <h1 style="font-size: 2.5rem; margin: 0;">🔒 SkyTrace </h1>
    <p style="font-size: 1.2rem; opacity: 0.9; margin-top: 10px;">
      <h2> AI-Powered Security Anomaly Detection </h2>
      <span style="font-size: 0.9rem;">Real-time monitoring • AI/ML Detection • Risk Intelligence </span>
    </p>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.globe.min.js"></script>
<script>
VANTA.GLOBE({
  el: "#vanta-hero",
  mouseControls: true,
  touchControls: true,
  gyroControls: false,
  minHeight: 200.00,
  minWidth: 200.00,
  scale: 1.00,
  scaleMobile: 1.00,
  color: 0xf94b4b,
  backgroundColor: 0x0e1117
})
</script>
"""
components.html(hero_section, height=320)

# --- Rest of the page content ---
st.markdown("---")

# Overview section
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="Data Status",
        value="Ready" if st.session_state.login_data is not None else "No Data",
        delta="Active" if st.session_state.login_data is not None else "Upload Required"
    )

with col2:
    st.metric(
        label="Anomalies Detected",
        value=len(st.session_state.anomaly_results) if st.session_state.anomaly_results is not None else 0,
        delta="Real-time"
    )

with col3:
    st.metric(
        label="Risk Threshold",
        value=f"{st.session_state.risk_threshold:.1%}",
        delta="Configurable"
    )

with col4:
    st.metric(
        label="System Status",
        value="Online",
        delta="Monitoring"
    )

st.markdown("---")

# System overview
st.header("🏗️ System Overview")

col1, col2 = st.columns(2)

with col1:
    st.subheader("🤖 AI/ML Detection Features")
    st.markdown("""
    - **Isolation Forest**: Unsupervised anomaly detection
    - **DBSCAN Clustering**: Outlier pattern identification
    - **Statistical Analysis**: Rule-based anomaly flagging
    - **Risk Scoring**: 0-1 scale threat prioritization
    """)
    
    st.subheader("🌍 Security Intelligence")
    st.markdown("""
    - **Geolocation Analysis**: IP-to-location mapping
    - **Impossible Travel**: Time/distance calculations
    - **Device Fingerprinting**: Browser, OS consistency
    - **Behavioral Baselines**: Personalized detection
    """)

with col2:
    st.subheader("📊 Monitoring & Reporting")
    st.markdown("""
    - **Real-time Dashboard**: Live security metrics
    - **Interactive Maps**: Login locations and anomalies
    - **Time-series Analysis**: Login pattern trends
    - **User Risk Profiles**: Individual threat assessment
    """)
    
    st.subheader("🔒 Security Features")
    st.markdown("""
    - **Risk Threshold Config**: Customizable sensitivity
    - **Alert Classification**: Low/Medium/High/Critical
    - **Historical Analysis**: Custom date ranges
    - **Export Capabilities**: CSV, reports, notifications
    """)

st.markdown("---")

# Workflow guidance
st.header("🚀 Getting Started")
st.markdown("""
Follow these steps to analyze your login data for security anomalies:

1. **📤 Data Upload**: Upload your CSV file with login records (timestamp, user_id, IP, user_agent)
2. **🤖 Anomaly Detection**: Run AI/ML algorithms to detect suspicious patterns
3. **📈 Real-time Dashboard**: Monitor live security metrics and geographical analysis
4. **📋 Security Reports**: Generate comprehensive reports and export results
""")

# Quick actions
st.header("⚡ Quick Actions")
col1, col2, col3, col4 = st.columns(4)

with col1:
    if st.button("📤 Upload Data", use_container_width=True):
        st.switch_page("pages/1_Data_Upload.py")

with col2:
    if st.button("🤖 Run Detection", use_container_width=True):
        if st.session_state.login_data is not None:
            st.switch_page("pages/2_Anomaly_Detection.py")
        else:
            st.error("Please upload data first!")

with col3:
    if st.button("📈 View Dashboard", use_container_width=True):
        st.switch_page("pages/3_Real_time_Dashboard.py")

with col4:
    if st.button("📋 Generate Reports", use_container_width=True):
        st.switch_page("pages/4_Security_Reports.py")

# System configuration
st.markdown("---")
st.header("⚙️ System Configuration")

col1, col2 = st.columns(2)

with col1:
    new_threshold = st.slider(
        "Risk Threshold",
        min_value=0.1,
        max_value=1.0,
        value=st.session_state.risk_threshold,
        step=0.1,
        help="Anomalies with risk scores above this threshold will be flagged"
    )
    if new_threshold != st.session_state.risk_threshold:
        st.session_state.risk_threshold = new_threshold
        st.success(f"Risk threshold updated to {new_threshold:.1%}")

with col2:
    st.subheader("Data Information")
    if st.session_state.login_data is not None:
        st.info(f"Loaded {len(st.session_state.login_data)} login records")
        st.info(f"Date range: {st.session_state.login_data['timestamp'].min()} to {st.session_state.login_data['timestamp'].max()}")
    else:
        st.warning("No data loaded. Please upload login data to begin analysis.")

# Footer
st.markdown("---")
st.markdown("*AI-Powered Security Anomaly Detection System - Built with Streamlit*")

st.markdown("""
<div style="position: fixed; bottom: 20px; right: 20px; z-index: 1000;">
    <iframe 
        src="https://builder.corover.ai/params/?appid=b9a4faa1-abed-4eef-a28a-7caddb277e3a#" 
        style="width: 350px; height: 500px; border: none; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"
        sandbox="allow-scripts allow-same-origin allow-forms"
        title="Customer Support Chatbot">
    </iframe>
</div>
""", unsafe_allow_html=True)
