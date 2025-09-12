import streamlit as st
import pandas as pd
from utils.report_generator import SecurityReportGenerator
from utils.visualizations import SecurityVisualizations
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import io
import base64

# Configure page
st.set_page_config(
    page_title="Security Reports - AI Security System",
    page_icon="📋",
    layout="wide"
)

st.title("📋 Security Reports & Analysis")
st.markdown("Generate comprehensive security reports and export analysis results")

# Check if data is available
if st.session_state.login_data is None:
    st.warning("⚠️ No data available. Please upload login data first.")
    if st.button("📤 Go to Data Upload"):
        st.switch_page("pages/1_Data_Upload.py")
    st.stop()

# Check if anomaly detection has been run
has_anomaly_results = st.session_state.anomaly_results is not None

if not has_anomaly_results:
    st.warning("⚠️ No anomaly detection results available. Please run anomaly detection first.")
    if st.button("🤖 Run Anomaly Detection"):
        st.switch_page("pages/2_Anomaly_Detection.py")
    st.stop()

# Get data from session state
df = st.session_state.login_data.copy()
results_df = st.session_state.anomaly_results.copy()
anomaly_summary = st.session_state.get('anomaly_summary', {})
geo_analysis = st.session_state.get('geo_analysis', {})

# Initialize report generator and visualizations
report_gen = SecurityReportGenerator()
viz = SecurityVisualizations()

# Analysis results for reports
analysis_results = {
    'anomaly_summary': anomaly_summary,
    'geographical': geo_analysis
}

# Report Generation Section
st.header("📊 Report Generation")

# Report type selection
col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("📈 Executive Summary")
    st.markdown("High-level overview for management and stakeholders")
    
    if st.button("Generate Executive Report", use_container_width=True, type="primary"):
        with st.spinner("Generating executive summary..."):
            exec_report = report_gen.generate_executive_summary(results_df, analysis_results)
            st.session_state.executive_report = exec_report
            st.success("✅ Executive report generated!")

with col2:
    st.subheader("🔬 Technical Analysis")
    st.markdown("Detailed technical report for security teams")
    
    if st.button("Generate Technical Report", use_container_width=True, type="primary"):
        with st.spinner("Generating technical analysis..."):
            tech_report = report_gen._generate_technical_report(results_df, analysis_results)
            st.session_state.technical_report = tech_report
            st.success("✅ Technical report generated!")

with col3:
    st.subheader("🚨 Incident Report")
    st.markdown("Focused report on critical security incidents")
    
    if st.button("Generate Incident Report", use_container_width=True, type="primary"):
        with st.spinner("Generating incident report..."):
            incident_report = report_gen._generate_incident_report(results_df, analysis_results)
            st.session_state.incident_report = incident_report
            st.success("✅ Incident report generated!")

# Display Generated Reports
st.header("📄 Generated Reports")

# Tabs for different report types
report_tabs = st.tabs(["Executive Summary", "Technical Analysis", "Incident Report"])

with report_tabs[0]:
    if 'executive_report' in st.session_state:
        st.markdown(st.session_state.executive_report)
        
        # Download button
        if st.button("📥 Download Executive Report", key="download_exec"):
            report_bytes = st.session_state.executive_report.encode('utf-8')
            st.download_button(
                label="Download as Text File",
                data=report_bytes,
                file_name=f"executive_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    else:
        st.info("Generate an executive report to view it here.")

with report_tabs[1]:
    if 'technical_report' in st.session_state:
        st.markdown(st.session_state.technical_report)
        
        # Download button
        if st.button("📥 Download Technical Report", key="download_tech"):
            report_bytes = st.session_state.technical_report.encode('utf-8')
            st.download_button(
                label="Download as Text File",
                data=report_bytes,
                file_name=f"technical_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    else:
        st.info("Generate a technical report to view it here.")

with report_tabs[2]:
    if 'incident_report' in st.session_state:
        st.markdown(st.session_state.incident_report)
        
        # Download button
        if st.button("📥 Download Incident Report", key="download_incident"):
            report_bytes = st.session_state.incident_report.encode('utf-8')
            st.download_button(
                label="Download as Text File",
                data=report_bytes,
                file_name=f"incident_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    else:
        st.info("Generate an incident report to view it here.")

# Data Export Section
st.header("📤 Data Export")

col1, col2 = st.columns(2)

with col1:
    st.subheader("🔍 Anomaly Data Export")
    
    # Filter options for export
    export_risk_level = st.selectbox(
        "Risk Level Filter for Export",
        options=['All', 'Low', 'Medium', 'High', 'Critical'],
        help="Select which risk levels to include in export"
    )
    
    export_date_range = st.date_input(
        "Date Range for Export",
        value=(results_df['timestamp'].min().date(), results_df['timestamp'].max().date()),
        help="Select date range for export"
    )
    
    # Apply filters for export
    export_df = results_df.copy()
    
    if export_risk_level != 'All':
        export_df = export_df[export_df['risk_level'] == export_risk_level]
    
    if len(export_date_range) == 2:
        start_date, end_date = export_date_range
        export_df = export_df[
            (export_df['timestamp'].dt.date >= start_date) &
            (export_df['timestamp'].dt.date <= end_date)
        ]
    
    st.info(f"Export will include {len(export_df):,} records")
    
    if st.button("📥 Export Filtered Data", use_container_width=True):
        try:
            csv_data = report_gen.export_anomaly_data(export_df, format_type='csv')
            
            st.download_button(
                label="Download CSV File",
                data=csv_data,
                file_name=f"anomaly_data_{export_risk_level.lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
            st.success("✅ Export file prepared for download!")
        except Exception as e:
            st.error(f"Export failed: {str(e)}")

with col2:
    st.subheader("📊 Analysis Summary Export")
    
    # Create summary data for export
    summary_data = {
        'Analysis Date': [datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        'Total Records': [len(results_df)],
        'High Risk Events': [len(results_df[results_df['risk_score'] >= 0.6])],
        'Critical Events': [len(results_df[results_df['risk_score'] >= 0.8])],
        'Unique Users': [results_df['user_id'].nunique()],
        'Unique Countries': [results_df['country'].nunique() if 'country' in results_df.columns else 0],
        'Average Risk Score': [results_df['risk_score'].mean()],
        'Risk Threshold Used': [st.session_state.risk_threshold]
    }
    
    # Add geographical analysis if available
    if geo_analysis:
        if 'impossible_travel' in geo_analysis:
            summary_data['Impossible Travel Incidents'] = [geo_analysis['impossible_travel'].get('total_incidents', 0)]
        if 'vpn_usage' in geo_analysis:
            summary_data['VPN Usage Percentage'] = [geo_analysis['vpn_usage'].get('vpn_percentage', 0)]
    
    summary_df = pd.DataFrame(summary_data)
    
    st.dataframe(summary_df.T, use_container_width=True, column_config={0: "Value"})
    
    if st.button("📥 Export Analysis Summary", use_container_width=True):
        csv_summary = summary_df.to_csv(index=False)
        st.download_button(
            label="Download Summary CSV",
            data=csv_summary,
            file_name=f"analysis_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

# Alert Configuration Section
st.header("⚙️ Alert Configuration")

col1, col2 = st.columns(2)

with col1:
    st.subheader("🎯 Risk Thresholds")
    
    alert_config = report_gen.get_alert_configuration()
    
    # Current thresholds
    st.markdown("**Current Risk Thresholds:**")
    for level, threshold in alert_config['risk_thresholds'].items():
        count = len(results_df[results_df['risk_score'] >= threshold]) if threshold > 0 else len(results_df)
        st.markdown(f"• **{level.title()}**: ≥ {threshold:.1f} ({count:,} events)")
    
    # Threshold adjustment
    st.markdown("**Adjust Alert Threshold:**")
    new_threshold = st.slider(
        "Alert Threshold",
        min_value=0.1,
        max_value=1.0,
        value=st.session_state.risk_threshold,
        step=0.1,
        help="Events above this threshold will trigger alerts"
    )
    
    if new_threshold != st.session_state.risk_threshold:
        st.session_state.risk_threshold = new_threshold
        st.success(f"Alert threshold updated to {new_threshold:.1f}")
        st.rerun()

with col2:
    st.subheader("📧 Notification Settings")
    
    st.markdown("**Recommended Alert Conditions:**")
    for frequency, conditions in alert_config['alert_conditions'].items():
        st.markdown(f"• **{frequency.title()}**: {', '.join(conditions)}")
    
    st.markdown("**Notification Channels:**")
    for channel, contact in alert_config['notification_channels'].items():
        st.markdown(f"• **{channel.title()}**: {contact}")
    
    # Schedule configuration
    st.markdown("**Report Scheduling:**")
    schedule_frequency = st.selectbox(
        "Report Frequency",
        options=['Manual', 'Daily', 'Weekly', 'Monthly'],
        help="How often to generate automated reports"
    )
    
    if schedule_frequency != 'Manual':
        st.info(f"Automated {schedule_frequency.lower()} reports would be configured in production environment")

# Analytics and Trends Section
st.header("📈 Analytics & Trends")

# Time-based analysis
col1, col2 = st.columns(2)

with col1:
    st.subheader("⏰ Temporal Analysis")
    
    # Hourly risk distribution
    results_df['hour'] = results_df['timestamp'].dt.hour
    hourly_risk = results_df.groupby('hour')['risk_score'].agg(['mean', 'count']).reset_index()
    
    fig_hourly = px.bar(
        hourly_risk,
        x='hour',
        y='mean',
        title='Average Risk Score by Hour',
        labels={'hour': 'Hour of Day', 'mean': 'Average Risk Score'},
        color='mean',
        color_continuous_scale='Reds'
    )
    st.plotly_chart(fig_hourly, use_container_width=True)

with col2:
    st.subheader("🌍 Geographical Risk")
    
    if 'country' in results_df.columns:
        country_risk = results_df.groupby('country')['risk_score'].agg(['mean', 'count']).reset_index()
        country_risk = country_risk.sort_values('mean', ascending=False).head(10)
        
        fig_country = px.bar(
            country_risk,
            x='country',
            y='mean',
            title='Average Risk Score by Country (Top 10)',
            labels={'country': 'Country', 'mean': 'Average Risk Score'},
            color='mean',
            color_continuous_scale='Reds'
        )
        fig_country.update_xaxes(tickangle=45)
        st.plotly_chart(fig_country, use_container_width=True)
    else:
        st.info("Geographical data not available. Run anomaly detection with geolocation enabled.")

# User Risk Analysis
st.subheader("👥 User Risk Analysis")

user_risk_analysis = results_df.groupby('user_id').agg({
    'risk_score': ['mean', 'max', 'std', 'count'],
    'timestamp': ['min', 'max']
}).round(3)

user_risk_analysis.columns = ['Avg Risk', 'Max Risk', 'Risk Std', 'Login Count', 'First Login', 'Last Login']
user_risk_analysis['Risk Consistency'] = user_risk_analysis['Risk Std'].apply(
    lambda x: 'Consistent' if x < 0.1 else 'Variable' if x < 0.3 else 'Highly Variable'
)

# Show top risk users
top_risk_users = user_risk_analysis.sort_values('Avg Risk', ascending=False).head(20)

col1, col2 = st.columns([2, 1])

with col1:
    st.dataframe(top_risk_users, use_container_width=True)

with col2:
    # Risk consistency distribution
    consistency_counts = user_risk_analysis['Risk Consistency'].value_counts()
    fig_consistency = px.pie(
        values=consistency_counts.values,
        names=consistency_counts.index,
        title='User Risk Consistency'
    )
    st.plotly_chart(fig_consistency, use_container_width=True)

# Scheduled Report Summary
st.header("📅 Scheduled Report Summary")

scheduled_summary = report_gen.generate_scheduled_report_summary(results_df)

col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("📊 Last 24 Hours")
    last_24h = scheduled_summary['last_24_hours']
    st.metric("Total Logins", f"{last_24h['total_logins']:,}")
    st.metric("High Risk Events", f"{last_24h['high_risk_events']:,}")
    st.metric("Critical Events", f"{last_24h['critical_events']:,}")

with col2:
    st.subheader("📊 Last Week")
    last_week = scheduled_summary['last_week']
    st.metric("Total Logins", f"{last_week['total_logins']:,}")
    st.metric("High Risk Events", f"{last_week['high_risk_events']:,}")
    st.metric("Critical Events", f"{last_week['critical_events']:,}")

with col3:
    st.subheader("📈 Trends")
    trends = scheduled_summary['trends']
    risk_trend = "📈" if trends['risk_score_trend'] == 'increasing' else "📉"
    activity_trend = "📈" if trends['activity_trend'] == 'increasing' else "📉"
    
    st.markdown(f"**Risk Trend**: {risk_trend} {trends['risk_score_trend'].title()}")
    st.markdown(f"**Activity Trend**: {activity_trend} {trends['activity_trend'].title()}")

# Action Items Section
st.header("🎯 Recommended Actions")

# Generate action items based on analysis
action_items = []

# High risk users
high_risk_users = len(results_df[results_df['risk_score'] >= 0.7]['user_id'].unique())
if high_risk_users > 0:
    action_items.append(f"🔴 **Critical**: Review {high_risk_users} users with consistently high risk scores")

# Impossible travel
if geo_analysis and 'impossible_travel' in geo_analysis:
    travel_incidents = geo_analysis['impossible_travel'].get('total_incidents', 0)
    if travel_incidents > 0:
        action_items.append(f"🚀 **Travel**: Investigate {travel_incidents} impossible travel incidents")

# VPN usage
if geo_analysis and 'vpn_usage' in geo_analysis:
    vpn_percentage = geo_analysis['vpn_usage'].get('vpn_percentage', 0)
    if vpn_percentage > 20:
        action_items.append(f"🔒 **VPN**: High VPN usage detected ({vpn_percentage:.1f}%) - review policy compliance")

# Weekend/unusual hours
weekend_logins = results_df.get('is_weekend_login', pd.Series([False])).sum()
unusual_hours = results_df.get('is_unusual_hours', pd.Series([False])).sum()

if weekend_logins > 0:
    action_items.append(f"📅 **Schedule**: {weekend_logins} weekend logins detected - verify business justification")

if unusual_hours > 0:
    action_items.append(f"🌙 **Hours**: {unusual_hours} unusual hour logins detected - check for after-hours policy violations")

# Display action items
if action_items:
    for item in action_items:
        st.markdown(item)
else:
    st.success("🎉 No immediate action items identified. Security posture appears normal.")

# Quick Actions
st.header("⚡ Quick Actions")

col1, col2, col3, col4 = st.columns(4)

with col1:
    if st.button("🔄 Refresh Analysis", use_container_width=True):
        st.rerun()

with col2:
    if st.button("📈 View Dashboard", use_container_width=True):
        st.switch_page("pages/3_Real_time_Dashboard.py")

with col3:
    if st.button("🤖 Re-run Detection", use_container_width=True):
        st.switch_page("pages/2_Anomaly_Detection.py")

with col4:
    if st.button("📤 Upload New Data", use_container_width=True):
        st.switch_page("pages/1_Data_Upload.py")

# Footer
st.markdown("---")
st.markdown(f"*Security reports generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Analysis covers {len(results_df):,} login events*")
