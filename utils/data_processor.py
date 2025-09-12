import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import re
from typing import Dict, List, Tuple, Optional
import streamlit as st

class DataProcessor:
    """Handles data validation, cleaning, and feature engineering for login records."""
    
    def __init__(self):
        self.required_columns = ['timestamp', 'user_id', 'ip_address', 'user_agent']
        
    def validate_data(self, df: pd.DataFrame) -> Tuple[bool, List[str]]:
        """
        Validate the uploaded data format and content.
        
        Args:
            df: DataFrame to validate
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Check required columns
        missing_cols = [col for col in self.required_columns if col not in df.columns]
        if missing_cols:
            errors.append(f"Missing required columns: {', '.join(missing_cols)}")
        
        if errors:
            return False, errors
            
        # Check data types and content
        if len(df) == 0:
            errors.append("Dataset is empty")
            
        # Validate timestamp format
        try:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        except:
            errors.append("Invalid timestamp format. Use YYYY-MM-DD HH:MM:SS or similar")
            
        # Validate IP addresses
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        invalid_ips = ~df['ip_address'].str.match(ip_pattern, na=False)
        if invalid_ips.any():
            errors.append(f"Found {invalid_ips.sum()} invalid IP addresses")
            
        # Check for missing values
        null_counts = df.isnull().sum()
        if null_counts.any():
            errors.append(f"Missing values found: {null_counts.to_dict()}")
            
        return len(errors) == 0, errors
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean and preprocess the data.
        
        Args:
            df: Raw DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        df_clean = df.copy()
        
        # Convert timestamp to datetime
        df_clean['timestamp'] = pd.to_datetime(df_clean['timestamp'])
        
        # Sort by timestamp
        df_clean = df_clean.sort_values('timestamp').reset_index(drop=True)
        
        # Remove duplicates
        initial_count = len(df_clean)
        df_clean = df_clean.drop_duplicates().reset_index(drop=True)
        if len(df_clean) < initial_count:
            st.info(f"Removed {initial_count - len(df_clean)} duplicate records")
        
        return df_clean
    
    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract behavioral and temporal features from login data.
        
        Args:
            df: Cleaned DataFrame
            
        Returns:
            DataFrame with additional feature columns
        """
        df_features = df.copy()
        
        # Time-based features
        df_features['hour'] = df_features['timestamp'].dt.hour
        df_features['day_of_week'] = df_features['timestamp'].dt.dayofweek
        df_features['is_weekend'] = df_features['day_of_week'].isin([5, 6]).astype(int)
        df_features['is_business_hours'] = ((df_features['hour'] >= 9) & 
                                          (df_features['hour'] <= 17)).astype(int)
        
        # Extract browser and OS information from user agent
        df_features['browser'] = df_features['user_agent'].apply(self._extract_browser)
        df_features['os'] = df_features['user_agent'].apply(self._extract_os)
        df_features['device_type'] = df_features['user_agent'].apply(self._extract_device_type)
        
        # User behavior features
        user_stats = self._calculate_user_statistics(df_features)
        df_features = df_features.merge(user_stats, on='user_id', how='left')
        
        return df_features
    
    def _extract_browser(self, user_agent: str) -> str:
        """Extract browser information from user agent string."""
        if pd.isna(user_agent):
            return 'Unknown'
        
        user_agent = user_agent.lower()
        if 'chrome' in user_agent:
            return 'Chrome'
        elif 'firefox' in user_agent:
            return 'Firefox'
        elif 'safari' in user_agent and 'chrome' not in user_agent:
            return 'Safari'
        elif 'edge' in user_agent:
            return 'Edge'
        elif 'opera' in user_agent:
            return 'Opera'
        else:
            return 'Other'
    
    def _extract_os(self, user_agent: str) -> str:
        """Extract operating system from user agent string."""
        if pd.isna(user_agent):
            return 'Unknown'
        
        user_agent = user_agent.lower()
        if 'windows' in user_agent:
            return 'Windows'
        elif 'mac' in user_agent or 'darwin' in user_agent:
            return 'macOS'
        elif 'linux' in user_agent:
            return 'Linux'
        elif 'android' in user_agent:
            return 'Android'
        elif 'iphone' in user_agent or 'ipad' in user_agent:
            return 'iOS'
        else:
            return 'Other'
    
    def _extract_device_type(self, user_agent: str) -> str:
        """Extract device type from user agent string."""
        if pd.isna(user_agent):
            return 'Unknown'
        
        user_agent = user_agent.lower()
        if 'mobile' in user_agent or 'android' in user_agent or 'iphone' in user_agent:
            return 'Mobile'
        elif 'tablet' in user_agent or 'ipad' in user_agent:
            return 'Tablet'
        else:
            return 'Desktop'
    
    def _calculate_user_statistics(self, df: pd.DataFrame) -> pd.DataFrame:
        """Calculate user behavior statistics."""
        user_stats = df.groupby('user_id').agg({
            'timestamp': ['count', 'min', 'max'],
            'ip_address': 'nunique',
            'browser': 'nunique',
            'os': 'nunique',
            'hour': lambda x: x.std(),
            'is_weekend': 'mean',
            'is_business_hours': 'mean'
        }).reset_index()
        
        # Flatten column names
        user_stats.columns = ['user_id', 'login_count', 'first_login', 'last_login',
                             'unique_ips', 'unique_browsers', 'unique_os',
                             'hour_std', 'weekend_ratio', 'business_hours_ratio']
        
        # Calculate login frequency (logins per day)
        user_stats['days_active'] = (user_stats['last_login'] - user_stats['first_login']).dt.days + 1
        user_stats['login_frequency'] = user_stats['login_count'] / user_stats['days_active']
        user_stats['login_frequency'] = user_stats['login_frequency'].fillna(user_stats['login_count'])
        
        return user_stats
    
    def get_data_summary(self, df: pd.DataFrame) -> Dict:
        """Generate a summary of the dataset."""
        summary = {
            'total_records': len(df),
            'unique_users': df['user_id'].nunique(),
            'unique_ips': df['ip_address'].nunique(),
            'date_range': {
                'start': df['timestamp'].min(),
                'end': df['timestamp'].max(),
                'days': (df['timestamp'].max() - df['timestamp'].min()).days + 1
            },
            'browsers': df['browser'].value_counts().to_dict() if 'browser' in df.columns else {},
            'operating_systems': df['os'].value_counts().to_dict() if 'os' in df.columns else {},
            'device_types': df['device_type'].value_counts().to_dict() if 'device_type' in df.columns else {}
        }
        
        return summary
