import streamlit as st
import pandas as pd
from utils.data_processor import DataProcessor
import io

# Configure page
st.set_page_config(
    page_title="Data Upload - AI Security System",
    page_icon="📤",
    layout="wide"
)

st.title("📤 Data Upload & Validation")
st.markdown("Upload your login data CSV file for security analysis")

# Initialize data processor
processor = DataProcessor()

# File upload section
st.header("Upload Login Data")

uploaded_file = st.file_uploader(
    "Choose a CSV file",
    type=['csv'],
    help="Upload a CSV file containing login records with columns: timestamp, user_id, ip_address, user_agent"
)

# Data format requirements
with st.expander("📋 Data Format Requirements", expanded=False):
    st.markdown("""
    Your CSV file must contain the following columns:
    
    | Column | Description | Example |
    |--------|-------------|---------|
    | `timestamp` | Login timestamp | 2024-01-15 09:30:45 |
    | `user_id` | Unique user identifier | user123 |
    | `ip_address` | IP address of login | 192.168.1.100 |
    | `user_agent` | Browser user agent string | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 |
    
    **Supported timestamp formats:**
    - YYYY-MM-DD HH:MM:SS
    - YYYY/MM/DD HH:MM:SS
    - MM/DD/YYYY HH:MM:SS
    - ISO format with timezone
    """)

# Sample data download
st.header("📋 Sample Data Template")
col1, col2 = st.columns(2)

with col1:
    st.markdown("Download a sample CSV template to understand the required format:")
    
    # Create sample data
    sample_data = {
        'timestamp': [
            '2024-01-15 09:30:45',
            '2024-01-15 10:15:22',
            '2024-01-15 11:45:10',
            '2024-01-15 14:20:33',
            '2024-01-15 16:55:17'
        ],
        'user_id': [
            'user001',
            'user002',
            'user001',
            'user003',
            'user002'
        ],
        'ip_address': [
            '192.168.1.100',
            '10.0.0.45',
            '203.0.113.195',
            '198.51.100.78',
            '192.168.1.100'
        ],
        'user_agent': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101'
        ]
    }
    
    sample_df = pd.DataFrame(sample_data)
    csv_sample = sample_df.to_csv(index=False)
    
    st.download_button(
        label="📥 Download Sample Template",
        data=csv_sample,
        file_name="login_data_template.csv",
        mime="text/csv"
    )

with col2:
    st.markdown("**Sample Data Preview:**")
    st.dataframe(sample_df, use_container_width=True)

# Process uploaded file
if uploaded_file is not None:
    try:
        # Read the uploaded file
        df = pd.read_csv(uploaded_file)
        
        st.header("📊 Data Validation Results")
        
        # Validate data
        is_valid, errors = processor.validate_data(df)
        
        if is_valid:
            # Success message
            st.success("✅ Data validation successful!")
            
            # Clean and process data
            with st.spinner("Processing data..."):
                df_clean = processor.clean_data(df)
                df_features = processor.extract_features(df_clean)
            
            # Display data summary
            summary = processor.get_data_summary(df_features)
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Records", f"{summary['total_records']:,}")
            with col2:
                st.metric("Unique Users", f"{summary['unique_users']:,}")
            with col3:
                st.metric("Unique IPs", f"{summary['unique_ips']:,}")
            with col4:
                st.metric("Date Range", f"{summary['date_range']['days']} days")
            
            # Data preview
            st.subheader("📋 Data Preview")
            preview_columns = ['timestamp', 'user_id', 'ip_address', 'browser', 'os', 'device_type']
            available_preview = [col for col in preview_columns if col in df_features.columns]
            st.dataframe(df_features[available_preview].head(10), use_container_width=True)
            
            # Additional statistics
            st.subheader("📈 Data Statistics")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Browser Distribution**")
                if summary['browsers']:
                    browser_df = pd.DataFrame(list(summary['browsers'].items()), 
                                            columns=['Browser', 'Count'])
                    st.dataframe(browser_df, use_container_width=True)
                else:
                    st.info("Browser information not available")
            
            with col2:
                st.markdown("**Operating System Distribution**")
                if summary['operating_systems']:
                    os_df = pd.DataFrame(list(summary['operating_systems'].items()), 
                                       columns=['OS', 'Count'])
                    st.dataframe(os_df, use_container_width=True)
                else:
                    st.info("OS information not available")
            
            # Device type distribution
            if summary['device_types']:
                st.markdown("**Device Type Distribution**")
                device_df = pd.DataFrame(list(summary['device_types'].items()), 
                                       columns=['Device Type', 'Count'])
                st.dataframe(device_df, use_container_width=True)
            
            # Save to session state
            st.session_state.login_data = df_features
            st.session_state.data_summary = summary
            
            # Next steps
            st.header("🚀 Next Steps")
            st.markdown("Your data has been successfully uploaded and processed. You can now:")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("🤖 Run Anomaly Detection", use_container_width=True):
                    st.switch_page("pages/2_Anomaly_Detection.py")
            
            with col2:
                if st.button("📈 View Dashboard", use_container_width=True):
                    st.switch_page("pages/3_Real_time_Dashboard.py")
            
            with col3:
                if st.button("📋 Generate Reports", use_container_width=True):
                    st.switch_page("pages/4_Security_Reports.py")
            
        else:
            # Display validation errors
            st.error("❌ Data validation failed!")
            
            for error in errors:
                st.error(f"• {error}")
            
            st.markdown("**Please fix the following issues and re-upload your file:**")
            st.markdown("1. Ensure all required columns are present")
            st.markdown("2. Check timestamp format")
            st.markdown("3. Validate IP address format")
            st.markdown("4. Remove any missing values")
    
    except Exception as e:
        st.error(f"Error reading file: {str(e)}")
        st.markdown("**Common issues:**")
        st.markdown("• File encoding - try saving as UTF-8")
        st.markdown("• Column separators - ensure comma-separated values")
        st.markdown("• File corruption - try re-exporting from source")

else:
    # Instructions when no file is uploaded
    st.header("🎯 Getting Started")
    st.markdown("""
    To begin your security analysis:
    
    1. **Prepare your data**: Ensure your CSV file contains the required columns
    2. **Upload the file**: Use the file uploader above
    3. **Review validation**: Check that your data passes all validation checks
    4. **Proceed to analysis**: Move to anomaly detection once data is validated
    
    If you don't have real data yet, download our sample template to test the system.
    """)
    
    # Display current session state
    if st.session_state.login_data is not None:
        st.info("💡 You have previously uploaded data. You can proceed to other sections or upload new data to replace it.")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Current Dataset", f"{len(st.session_state.login_data):,} records")
        with col2:
            if st.button("🗑️ Clear Current Data", type="secondary"):
                st.session_state.login_data = None
                st.session_state.anomaly_results = None
                st.rerun()

# Footer information
st.markdown("---")
st.markdown("*Upload your login data to begin AI-powered security analysis*")
