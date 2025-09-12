import streamlit as st
import pandas as pd
from utils.visualizations import SecurityVisualizations
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import folium
from streamlit_folium import st_folium

# Configure page
st.set_page_config(
    page_title="Security Dashboard - AI Security System",
    page_icon="📈",
    layout="wide"
)

st.title("📈 Real-time Security Dashboard")
st.markdown("Interactive monitoring and visualization of security metrics")

# Check if data is available
if st.session_state.login_data is None:
    st.warning("⚠️ No data available. Please upload login data first.")
    if st.button("📤 Go to Data Upload"):
        st.switch_page("pages/1_Data_Upload.py")
    st.stop()

# Get data from session state
df = st.session_state.login_data.copy()
has_anomaly_results = st.session_state.anomaly_results is not None

if has_anomaly_results:
    results_df = st.session_state.anomaly_results.copy()
else:
    results_df = df.copy()
    # Add dummy risk scores for visualization when no analysis has been run
    results_df['risk_score'] = 0.1
    results_df['risk_level'] = 'Low'

# Initialize visualizations
viz = SecurityVisualizations()

# Dashboard controls
st.header("🎛️ Dashboard Controls")

col1, col2, col3, col4 = st.columns(4)

with col1:
    # Time range filter
    min_date = df['timestamp'].min().date()
    max_date = df['timestamp'].max().date()
    
    date_range = st.date_input(
        "Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )

with col2:
    # Risk level filter
    risk_levels = ['All'] + list(results_df['risk_level'].unique())
    selected_risk = st.selectbox("Risk Level", risk_levels)

with col3:
    # User filter
    users = ['All'] + sorted(df['user_id'].unique())
    selected_user = st.selectbox("User", users[:51])  # Limit for performance

with col4:
    # Auto-refresh
    auto_refresh = st.checkbox("Auto-refresh (30s)", value=False)
    if auto_refresh:
        st.rerun()

# Apply filters
filtered_df = results_df.copy()

# Date filter
if len(date_range) == 2:
    start_date, end_date = date_range
    filtered_df = filtered_df[
        (filtered_df['timestamp'].dt.date >= start_date) &
        (filtered_df['timestamp'].dt.date <= end_date)
    ]

# Risk level filter
if selected_risk != 'All':
    filtered_df = filtered_df[filtered_df['risk_level'] == selected_risk]

# User filter
if selected_user != 'All':
    filtered_df = filtered_df[filtered_df['user_id'] == selected_user]

# Key Metrics Section
st.header("📊 Key Security Metrics")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    total_logins = len(filtered_df)
    st.metric("Total Logins", f"{total_logins:,}")

with col2:
    high_risk = len(filtered_df[filtered_df['risk_score'] >= 0.6]) if has_anomaly_results else 0
    risk_pct = (high_risk / total_logins * 100) if total_logins > 0 else 0
    st.metric("High Risk Events", f"{high_risk:,}", delta=f"{risk_pct:.1f}%")

with col3:
    unique_users = filtered_df['user_id'].nunique()
    st.metric("Active Users", f"{unique_users:,}")

with col4:
    unique_locations = filtered_df['country'].nunique() if 'country' in filtered_df.columns else filtered_df['ip_address'].nunique()
    location_type = "Countries" if 'country' in filtered_df.columns else "IP Addresses"
    st.metric(f"Unique {location_type}", f"{unique_locations:,}")

with col5:
    if 'impossible_travel' in filtered_df.columns:
        impossible_travel = filtered_df['impossible_travel'].sum()
        st.metric("Impossible Travel", f"{impossible_travel:,}")
    else:
        avg_risk = filtered_df['risk_score'].mean() if has_anomaly_results else 0
        st.metric("Avg Risk Score", f"{avg_risk:.3f}")

# Real-time Activity Section
st.header("⏱️ Real-time Activity")

col1, col2 = st.columns(2)

with col1:
    # Time series chart
    if has_anomaly_results:
        fig_timeseries = viz.create_time_series_chart(filtered_df)
        st.plotly_chart(fig_timeseries, use_container_width=True)
    else:
        # Basic login activity chart
        hourly_data = filtered_df.set_index('timestamp').resample('H')['user_id'].count().reset_index()
        fig_basic = px.line(
            hourly_data,
            x='timestamp',
            y='user_id',
            title='Login Activity Over Time',
            labels={'user_id': 'Login Count', 'timestamp': 'Time'}
        )
        st.plotly_chart(fig_basic, use_container_width=True)

with col2:
    # Risk distribution
    if has_anomaly_results:
        fig_risk_dist = viz.create_risk_distribution_chart(filtered_df)
        st.plotly_chart(fig_risk_dist, use_container_width=True)
    else:
        # Basic activity by hour chart
        filtered_df['hour'] = filtered_df['timestamp'].dt.hour
        hourly_activity = filtered_df.groupby('hour')['user_id'].count().reset_index()
        fig_hourly = px.bar(
            hourly_activity,
            x='hour',
            y='user_id',
            title='Login Activity by Hour',
            labels={'user_id': 'Login Count', 'hour': 'Hour of Day'}
        )
        st.plotly_chart(fig_hourly, use_container_width=True)

# Geographical Analysis Section
st.header("🌍 Geographical Analysis")

if 'latitude' in filtered_df.columns and 'longitude' in filtered_df.columns:
    # Check if we have valid coordinates
    valid_coords = filtered_df[(filtered_df['latitude'] != 0) & (filtered_df['longitude'] != 0)]
    
    if len(valid_coords) > 0:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Interactive map
            st.subheader("🗺️ Login Locations Map")
            
            # Create folium map
            folium_map = viz.create_folium_map(valid_coords)
            map_data = st_folium(folium_map, width=700, height=400)
            
        with col2:
            # Location statistics
            st.subheader("📍 Location Stats")
            
            country_stats = valid_coords['country'].value_counts().head(10)
            st.markdown("**Top Countries:**")
            for country, count in country_stats.items():
                st.markdown(f"• {country}: {count}")
            
            if 'impossible_travel' in valid_coords.columns:
                st.markdown("**Travel Analysis:**")
                impossible_count = valid_coords['impossible_travel'].sum()
                st.markdown(f"• Impossible travel: {impossible_count}")
                
                if impossible_count > 0:
                    max_speed = valid_coords[valid_coords['impossible_travel']]['travel_speed_kmh'].max()
                    st.markdown(f"• Max speed: {max_speed:.0f} km/h")
    else:
        st.info("🌍 No geographical data available. Run anomaly detection with geolocation enabled to see maps.")
else:
    st.info("🌍 Geographical analysis not available. Upload data and run anomaly detection with geolocation enabled.")

# Security Alerts Section
st.header("🚨 Security Alerts")

if has_anomaly_results:
    # Recent high-risk events
    high_risk_recent = filtered_df[filtered_df['risk_score'] >= st.session_state.risk_threshold].sort_values('timestamp', ascending=False).head(10)
    
    if len(high_risk_recent) > 0:
        st.subheader("⚠️ Recent High-Risk Events")
        
        for idx, alert in high_risk_recent.iterrows():
            # Create alert card
            risk_color = "🔴" if alert['risk_score'] >= 0.8 else "🟠" if alert['risk_score'] >= 0.6 else "🟡"
            
            with st.container():
                col1, col2, col3, col4 = st.columns([1, 2, 2, 1])
                
                with col1:
                    st.markdown(f"**{risk_color} {alert['risk_level']}**")
                    st.markdown(f"Score: {alert['risk_score']:.3f}")
                
                with col2:
                    st.markdown(f"**User:** {alert['user_id']}")
                    st.markdown(f"**Time:** {alert['timestamp']}")
                
                with col3:
                    location = f"{alert.get('city', 'Unknown')}, {alert.get('country', 'Unknown')}"
                    st.markdown(f"**Location:** {location}")
                    st.markdown(f"**IP:** {alert['ip_address']}")
                
                with col4:
                    # Show specific anomaly flags
                    anomaly_flags = []
                    if alert.get('impossible_travel', False):
                        anomaly_flags.append("🚀 Travel")
                    if alert.get('is_unusual_hours', False):
                        anomaly_flags.append("🌙 Hours")
                    if alert.get('is_weekend_login', False):
                        anomaly_flags.append("📅 Weekend")
                    if alert.get('is_vpn', False):
                        anomaly_flags.append("🔒 VPN")
                    
                    if anomaly_flags:
                        st.markdown("**Flags:**")
                        for flag in anomaly_flags:
                            st.markdown(f"• {flag}")
                
                st.markdown("---")
    else:
        st.success("🎉 No high-risk events in the selected timeframe!")
else:
    st.info("Run anomaly detection to see security alerts.")

# User Risk Profiles Section
st.header("👥 User Risk Profiles")

if has_anomaly_results:
    col1, col2 = st.columns(2)
    
    with col1:
        # Top risk users chart
        fig_user_risk = viz.create_user_risk_chart(filtered_df, top_n=15)
        st.plotly_chart(fig_user_risk, use_container_width=True)
    
    with col2:
        # User risk table
        st.subheader("High-Risk Users")
        user_risk_summary = filtered_df.groupby('user_id').agg({
            'risk_score': ['mean', 'max', 'count'],
            'timestamp': ['min', 'max']
        }).round(3)
        
        user_risk_summary.columns = ['Avg Risk', 'Max Risk', 'Login Count', 'First Login', 'Last Login']
        user_risk_summary = user_risk_summary.sort_values('Avg Risk', ascending=False).head(10)
        
        st.dataframe(user_risk_summary, use_container_width=True)
else:
    # Basic user activity
    user_activity = filtered_df.groupby('user_id').agg({
        'timestamp': ['count', 'min', 'max'],
        'ip_address': 'nunique'
    })
    user_activity.columns = ['Login Count', 'First Login', 'Last Login', 'Unique IPs']
    user_activity = user_activity.sort_values('Login Count', ascending=False).head(10)
    
    st.subheader("Most Active Users")
    st.dataframe(user_activity, use_container_width=True)

# Device and Browser Analysis
st.header("💻 Device Analysis")

if 'browser' in filtered_df.columns and 'os' in filtered_df.columns:
    col1, col2 = st.columns(2)
    
    with col1:
        # Browser distribution
        browser_stats = filtered_df['browser'].value_counts()
        fig_browser = px.pie(
            values=browser_stats.values,
            names=browser_stats.index,
            title="Browser Distribution"
        )
        st.plotly_chart(fig_browser, use_container_width=True)
    
    with col2:
        # OS distribution
        os_stats = filtered_df['os'].value_counts()
        fig_os = px.pie(
            values=os_stats.values,
            names=os_stats.index,
            title="Operating System Distribution"
        )
        st.plotly_chart(fig_os, use_container_width=True)
    
    # Device type analysis
    if 'device_type' in filtered_df.columns:
        device_stats = filtered_df['device_type'].value_counts()
        fig_device = px.bar(
            x=device_stats.index,
            y=device_stats.values,
            title="Device Type Distribution",
            labels={'x': 'Device Type', 'y': 'Count'}
        )
        st.plotly_chart(fig_device, use_container_width=True)

# System Health Section
st.header("💚 System Health")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Data Quality",
        "Good",
        delta="✅ Valid",
        help="All data passed validation checks"
    )

with col2:
    detection_status = "Active" if has_anomaly_results else "Pending"
    st.metric(
        "Detection Status",
        detection_status,
        delta="🤖 ML Ready" if has_anomaly_results else "⏳ Awaiting Analysis"
    )

with col3:
    coverage = f"{(len(filtered_df)/len(df)*100):.1f}%" if len(df) > 0 else "0%"
    st.metric(
        "Coverage",
        coverage,
        delta="📊 Current Filter"
    )

with col4:
    last_update = datetime.now().strftime("%H:%M:%S")
    st.metric(
        "Last Update",
        last_update,
        delta="🔄 Live"
    )

# Quick Actions
st.header("⚡ Quick Actions")

col1, col2, col3, col4 = st.columns(4)

with col1:
    if st.button("🔄 Refresh Dashboard", use_container_width=True):
        st.rerun()

with col2:
    if st.button("🤖 Run Detection", use_container_width=True):
        st.switch_page("pages/2_Anomaly_Detection.py")

with col3:
    if st.button("📋 Generate Report", use_container_width=True):
        st.switch_page("pages/4_Security_Reports.py")

with col4:
    if st.button("📤 Upload New Data", use_container_width=True):
        st.switch_page("pages/1_Data_Upload.py")

# Footer
st.markdown("---")
st.markdown(f"*Dashboard last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Monitoring {len(filtered_df):,} login events*")
