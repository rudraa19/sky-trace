import streamlit as st
import pandas as pd
from utils.ml_detector import MLAnomalyDetector
from utils.geolocation import GeolocationAnalyzer
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# Configure page
st.set_page_config(
    page_title="Anomaly Detection - AI Security System",
    page_icon="🤖",
    layout="wide"
)

st.title("🤖 AI-Powered Anomaly Detection")
st.markdown("Run machine learning algorithms to detect suspicious login patterns")

# Check if data is available
if st.session_state.login_data is None:
    st.warning("⚠️ No data available. Please upload login data first.")
    if st.button("📤 Go to Data Upload"):
        st.switch_page("pages/1_Data_Upload.py")
    st.stop()

# Get data from session state
df = st.session_state.login_data.copy()

# Detection configuration
st.header("⚙️ Detection Configuration")

col1, col2, col3 = st.columns(3)

with col1:
    contamination_rate = st.slider(
        "Contamination Rate",
        min_value=0.01,
        max_value=0.3,
        value=0.1,
        step=0.01,
        help="Expected proportion of anomalies in the dataset"
    )

with col2:
    include_geolocation = st.checkbox(
        "Include Geolocation Analysis",
        value=True,
        help="Enrich data with geographical information (may take longer)"
    )

with col3:
    risk_threshold = st.slider(
        "Risk Alert Threshold",
        min_value=0.1,
        max_value=1.0,
        value=st.session_state.risk_threshold,
        step=0.1,
        help="Minimum risk score to flag as suspicious"
    )

# Update session state threshold
st.session_state.risk_threshold = risk_threshold

# Run detection button
st.header("🚀 Run Detection Analysis")

if st.button("🔍 Start Anomaly Detection", type="primary", use_container_width=True):
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        # Step 1: Initialize ML detector
        status_text.text("Initializing ML algorithms...")
        progress_bar.progress(10)
        
        detector = MLAnomalyDetector(contamination=contamination_rate)
        
        # Step 2: Geolocation enrichment (if enabled)
        if include_geolocation:
            status_text.text("Enriching data with geolocation information...")
            progress_bar.progress(20)
            
            geo_analyzer = GeolocationAnalyzer()
            df_enriched = geo_analyzer.enrich_with_geolocation(df)
            
            status_text.text("Analyzing impossible travel patterns...")
            progress_bar.progress(40)
            
            df_enriched = geo_analyzer.detect_impossible_travel(df_enriched)
        else:
            df_enriched = df.copy()
            progress_bar.progress(40)
        
        # Step 3: Run ML detection
        status_text.text("Running machine learning detection algorithms...")
        progress_bar.progress(60)
        
        results = detector.detect_anomalies(df_enriched)
        
        # Step 4: Generate analysis summary
        status_text.text("Generating analysis summary...")
        progress_bar.progress(80)
        
        anomaly_summary = detector.get_anomaly_summary(results)
        
        if include_geolocation:
            geo_analysis = geo_analyzer.analyze_geographical_patterns(results)
        else:
            geo_analysis = {}
        
        # Step 5: Save results
        status_text.text("Saving results...")
        progress_bar.progress(100)
        
        st.session_state.anomaly_results = results
        st.session_state.anomaly_summary = anomaly_summary
        st.session_state.geo_analysis = geo_analysis
        
        progress_bar.empty()
        status_text.empty()
        
        st.success("✅ Anomaly detection completed successfully!")
        
    except Exception as e:
        st.error(f"❌ Error during detection: {str(e)}")
        progress_bar.empty()
        status_text.empty()
        st.stop()

# Display results if available
if st.session_state.anomaly_results is not None:
    results_df = st.session_state.anomaly_results
    summary = st.session_state.anomaly_summary
    
    st.header("📊 Detection Results")
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Records Analyzed",
            f"{summary['total_records']:,}",
            help="Total number of login records processed"
        )
    
    with col2:
        st.metric(
            "Anomalies Detected",
            f"{summary['anomalies_detected']:,}",
            delta=f"{(summary['anomalies_detected']/summary['total_records']*100):.1f}%"
        )
    
    with col3:
        st.metric(
            "Average Risk Score",
            f"{summary['avg_risk_score']:.3f}",
            help="Average risk score across all records"
        )
    
    with col4:
        st.metric(
            "High-Risk Users",
            f"{summary['high_risk_users']:,}",
            help="Number of users with high risk scores"
        )
    
    # Risk level distribution
    st.subheader("🎯 Risk Level Distribution")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Risk level counts chart
        risk_counts = results_df['risk_level'].value_counts()
        colors = ['#2E8B57', '#FFD700', '#FF6347', '#DC143C']  # Green, Gold, Tomato, Crimson
        
        fig_pie = px.pie(
            values=risk_counts.values,
            names=risk_counts.index,
            title="Risk Level Distribution",
            color_discrete_sequence=colors
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # Risk score histogram
        fig_hist = px.histogram(
            results_df,
            x='risk_score',
            nbins=20,
            title="Risk Score Distribution",
            labels={'risk_score': 'Risk Score', 'count': 'Number of Records'}
        )
        
        # Add threshold line
        fig_hist.add_vline(
            x=risk_threshold,
            line_dash="dash",
            line_color="red",
            annotation_text=f"Alert Threshold ({risk_threshold})"
        )
        
        st.plotly_chart(fig_hist, use_container_width=True)
    
    # High-risk events table
    st.subheader("⚠️ High-Risk Events")
    
    high_risk_events = results_df[results_df['risk_score'] >= risk_threshold].copy()
    
    if len(high_risk_events) > 0:
        # Sort by risk score
        high_risk_events = high_risk_events.sort_values('risk_score', ascending=False)
        
        # Display configuration
        col1, col2 = st.columns(2)
        with col1:
            show_columns = st.multiselect(
                "Select columns to display:",
                options=['timestamp', 'user_id', 'ip_address', 'risk_score', 'risk_level', 
                        'city', 'country', 'browser', 'os', 'impossible_travel'],
                default=['timestamp', 'user_id', 'ip_address', 'risk_score', 'risk_level', 'city', 'country'],
                help="Choose which columns to show in the table"
            )
        
        with col2:
            max_rows = st.number_input(
                "Maximum rows to display:",
                min_value=10,
                max_value=1000,
                value=50,
                step=10
            )
        
        # Filter available columns
        available_columns = [col for col in show_columns if col in high_risk_events.columns]
        
        if available_columns:
            display_df = high_risk_events[available_columns].head(max_rows)
            
            # Format the dataframe for better display
            if 'risk_score' in display_df.columns:
                display_df['risk_score'] = display_df['risk_score'].round(3)
            if 'timestamp' in display_df.columns:
                display_df['timestamp'] = pd.to_datetime(display_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
            
            st.dataframe(display_df, use_container_width=True)
            
            # Export high-risk events
            if st.button("📥 Export High-Risk Events to CSV"):
                csv_data = high_risk_events.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name=f"high_risk_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        else:
            st.warning("No valid columns selected for display.")
    else:
        st.info("🎉 No high-risk events detected above the current threshold.")
    
    # Detection method breakdown
    st.subheader("🔬 Detection Method Analysis")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**Isolation Forest Anomalies**")
        isolation_anomalies = (results_df['isolation_score'] >= 0.7).sum()
        st.metric("Count", isolation_anomalies)
        st.markdown(f"*{(isolation_anomalies/len(results_df)*100):.1f}% of total*")
    
    with col2:
        st.markdown("**DBSCAN Outliers**")
        if 'is_dbscan_outlier' in results_df.columns:
            dbscan_outliers = results_df['is_dbscan_outlier'].sum()
            st.metric("Count", dbscan_outliers)
            st.markdown(f"*{(dbscan_outliers/len(results_df)*100):.1f}% of total*")
        else:
            st.info("Not available")
    
    with col3:
        st.markdown("**Statistical Anomalies**")
        if 'statistical_score' in results_df.columns:
            stat_anomalies = (results_df['statistical_score'] >= 0.5).sum()
            st.metric("Count", stat_anomalies)
            st.markdown(f"*{(stat_anomalies/len(results_df)*100):.1f}% of total*")
        else:
            st.info("Not available")
    
    # Statistical anomaly breakdown
    if any(col.startswith('is_') for col in results_df.columns):
        st.subheader("📈 Statistical Anomaly Breakdown")
        
        anomaly_stats = {}
        for col in results_df.columns:
            if col.startswith('is_') and col != 'is_dbscan_outlier':
                anomaly_name = col.replace('is_', '').replace('_', ' ').title()
                count = results_df[col].sum()
                if count > 0:
                    anomaly_stats[anomaly_name] = count
        
        if anomaly_stats:
            # Create bar chart
            fig_anomalies = px.bar(
                x=list(anomaly_stats.keys()),
                y=list(anomaly_stats.values()),
                title="Statistical Anomaly Types",
                labels={'x': 'Anomaly Type', 'y': 'Count'}
            )
            st.plotly_chart(fig_anomalies, use_container_width=True)
        else:
            st.info("No statistical anomalies detected.")
    
    # Geographical analysis (if available)
    if include_geolocation and 'geo_analysis' in st.session_state:
        geo_analysis = st.session_state.geo_analysis
        
        st.subheader("🌍 Geographical Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Location Diversity**")
            st.metric("Unique Countries", geo_analysis.get('unique_countries', 0))
            st.metric("Unique Cities", geo_analysis.get('unique_cities', 0))
        
        with col2:
            st.markdown("**Security Concerns**")
            if 'impossible_travel' in geo_analysis:
                travel_data = geo_analysis['impossible_travel']
                st.metric("Impossible Travel Incidents", travel_data.get('total_incidents', 0))
                if travel_data.get('max_speed_detected', 0) > 0:
                    st.metric("Max Speed Detected", f"{travel_data['max_speed_detected']:.0f} km/h")
            
            if 'vpn_usage' in geo_analysis:
                vpn_data = geo_analysis['vpn_usage']
                st.metric("VPN Logins", f"{vpn_data.get('vpn_percentage', 0):.1f}%")
    
    # Next steps
    st.header("🚀 Next Steps")
    st.markdown("Your anomaly detection is complete. You can now:")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📈 View Dashboard", use_container_width=True):
            st.switch_page("pages/3_Real_time_Dashboard.py")
    
    with col2:
        if st.button("📋 Generate Reports", use_container_width=True):
            st.switch_page("pages/4_Security_Reports.py")
    
    with col3:
        if st.button("🔄 Re-run Detection", use_container_width=True):
            st.rerun()

else:
    # Instructions when no results are available
    st.header("🎯 Ready to Detect Anomalies")
    st.markdown("""
    Configure your detection settings above and click "Start Anomaly Detection" to begin analysis.
    
    **What this analysis will do:**
    
    🤖 **Machine Learning Detection**
    - **Isolation Forest**: Identifies outliers in multi-dimensional feature space
    - **DBSCAN Clustering**: Finds density-based anomalies and outliers
    - **Statistical Analysis**: Rule-based detection for known threat patterns
    
    🌍 **Geolocation Analysis** (if enabled)
    - IP-to-location mapping for geographical context
    - Impossible travel detection based on time/distance calculations
    - VPN and proxy identification
    
    📊 **Risk Scoring**
    - Combines multiple detection methods into unified risk score (0-1)
    - Classifies threats as Low/Medium/High/Critical
    - Provides actionable insights for security teams
    """)

# Footer
st.markdown("---")
st.markdown("*AI-powered anomaly detection using advanced machine learning algorithms*")
