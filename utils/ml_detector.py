import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

class MLAnomalyDetector:
    """Machine learning based anomaly detection for login patterns."""
    
    def __init__(self, contamination=0.1):
        self.contamination = contamination
        self.isolation_forest = None
        self.dbscan = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_columns = []
        
    def prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Prepare features for ML algorithms.
        
        Args:
            df: DataFrame with extracted features
            
        Returns:
            DataFrame with encoded features ready for ML
        """
        feature_df = df.copy()
        
        # Select numerical features
        numerical_features = ['hour', 'day_of_week', 'is_weekend', 'is_business_hours',
                            'login_count', 'unique_ips', 'unique_browsers', 'unique_os',
                            'hour_std', 'weekend_ratio', 'business_hours_ratio', 'login_frequency']
        
        # Select categorical features to encode
        categorical_features = ['browser', 'os', 'device_type']
        
        # Encode categorical features
        for feature in categorical_features:
            if feature in feature_df.columns:
                if feature not in self.label_encoders:
                    self.label_encoders[feature] = LabelEncoder()
                    feature_df[f'{feature}_encoded'] = self.label_encoders[feature].fit_transform(feature_df[feature].astype(str))
                else:
                    # Handle unseen categories
                    known_categories = set(self.label_encoders[feature].classes_)
                    feature_df[feature] = feature_df[feature].astype(str)
                    unknown_mask = ~feature_df[feature].isin(known_categories)
                    feature_df.loc[unknown_mask, feature] = 'Unknown'
                    
                    # Add 'Unknown' to encoder if not present
                    if 'Unknown' not in known_categories:
                        self.label_encoders[feature].classes_ = np.append(self.label_encoders[feature].classes_, 'Unknown')
                    
                    feature_df[f'{feature}_encoded'] = self.label_encoders[feature].transform(feature_df[feature])
        
        # Prepare final feature matrix
        encoded_features = [f'{f}_encoded' for f in categorical_features if f in feature_df.columns]
        available_numerical = [f for f in numerical_features if f in feature_df.columns]
        
        self.feature_columns = available_numerical + encoded_features
        
        # Handle missing values
        feature_matrix = feature_df[self.feature_columns].fillna(0)
        
        return feature_matrix
    
    def detect_isolation_forest(self, feature_matrix: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Use Isolation Forest for anomaly detection.
        
        Args:
            feature_matrix: Prepared feature matrix
            
        Returns:
            Tuple of (anomaly_labels, anomaly_scores)
        """
        # Scale features
        X_scaled = self.scaler.fit_transform(feature_matrix)
        
        # Train Isolation Forest
        self.isolation_forest = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        
        # Predict anomalies (-1 for anomaly, 1 for normal)
        anomaly_labels = self.isolation_forest.fit_predict(X_scaled)
        
        # Get anomaly scores (lower is more anomalous)
        anomaly_scores = self.isolation_forest.score_samples(X_scaled)
        
        # Convert to 0-1 scale (higher is more anomalous)
        normalized_scores = 1 - ((anomaly_scores - anomaly_scores.min()) / 
                               (anomaly_scores.max() - anomaly_scores.min()))
        
        return anomaly_labels, normalized_scores
    
    def detect_dbscan_outliers(self, feature_matrix: pd.DataFrame) -> np.ndarray:
        """
        Use DBSCAN clustering to identify outliers.
        
        Args:
            feature_matrix: Prepared feature matrix
            
        Returns:
            Cluster labels (-1 for outliers)
        """
        # Scale features
        X_scaled = self.scaler.fit_transform(feature_matrix)
        
        # Apply PCA for dimensionality reduction if needed
        if X_scaled.shape[1] > 10:
            pca = PCA(n_components=min(10, X_scaled.shape[1]))
            X_scaled = pca.fit_transform(X_scaled)
        
        # DBSCAN clustering
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        cluster_labels = self.dbscan.fit_predict(X_scaled)
        
        return cluster_labels
    
    def statistical_anomaly_detection(self, df: pd.DataFrame) -> Dict[str, np.ndarray]:
        """
        Rule-based statistical anomaly detection.
        
        Args:
            df: DataFrame with features
            
        Returns:
            Dictionary of anomaly indicators for different rules
        """
        anomalies = {}
        
        # Time-based anomalies
        anomalies['unusual_hours'] = ((df['hour'] < 6) | (df['hour'] > 22)).values
        anomalies['weekend_login'] = (df['is_weekend'] == 1).values
        
        # Frequency-based anomalies
        if 'login_frequency' in df.columns:
            freq_threshold = df['login_frequency'].quantile(0.95)
            anomalies['high_frequency'] = (df['login_frequency'] > freq_threshold).values
        
        # Device inconsistency
        if 'unique_browsers' in df.columns:
            anomalies['multiple_browsers'] = (df['unique_browsers'] > 3).values
        if 'unique_os' in df.columns:
            anomalies['multiple_os'] = (df['unique_os'] > 2).values
        
        # IP address diversity
        if 'unique_ips' in df.columns:
            ip_threshold = df['unique_ips'].quantile(0.90)
            anomalies['multiple_ips'] = (df['unique_ips'] > ip_threshold).values
        
        return anomalies
    
    def calculate_risk_scores(self, df: pd.DataFrame, isolation_scores: np.ndarray,
                            dbscan_labels: np.ndarray, statistical_anomalies: Dict) -> pd.DataFrame:
        """
        Calculate comprehensive risk scores combining multiple detection methods.
        
        Args:
            df: Original DataFrame
            isolation_scores: Isolation Forest anomaly scores
            dbscan_labels: DBSCAN cluster labels
            statistical_anomalies: Statistical anomaly indicators
            
        Returns:
            DataFrame with risk scores and anomaly details
        """
        results = df.copy()
        
        # Add individual scores
        results['isolation_score'] = isolation_scores
        results['is_dbscan_outlier'] = (dbscan_labels == -1).astype(int)
        
        # Add statistical anomaly scores
        statistical_score = np.zeros(len(df))
        for anomaly_type, indicators in statistical_anomalies.items():
            results[f'is_{anomaly_type}'] = indicators.astype(int)
            statistical_score += indicators.astype(float)
        
        # Normalize statistical score
        if len(statistical_anomalies) > 0:
            results['statistical_score'] = statistical_score / len(statistical_anomalies)
        else:
            results['statistical_score'] = 0
        
        # Calculate combined risk score
        weights = {
            'isolation': 0.4,
            'dbscan': 0.3,
            'statistical': 0.3
        }
        
        results['risk_score'] = (
            weights['isolation'] * results['isolation_score'] +
            weights['dbscan'] * results['is_dbscan_outlier'] +
            weights['statistical'] * results['statistical_score']
        )
        
        # Risk level classification
        def classify_risk(score):
            if score >= 0.8:
                return 'Critical'
            elif score >= 0.6:
                return 'High'
            elif score >= 0.4:
                return 'Medium'
            else:
                return 'Low'
        
        results['risk_level'] = results['risk_score'].apply(classify_risk)
        
        return results
    
    def detect_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Main method to detect anomalies using all available methods.
        
        Args:
            df: DataFrame with extracted features
            
        Returns:
            DataFrame with anomaly detection results
        """
        # Prepare features for ML
        feature_matrix = self.prepare_features(df)
        
        # Run different detection methods
        isolation_labels, isolation_scores = self.detect_isolation_forest(feature_matrix)
        dbscan_labels = self.detect_dbscan_outliers(feature_matrix)
        statistical_anomalies = self.statistical_anomaly_detection(df)
        
        # Calculate comprehensive risk scores
        results = self.calculate_risk_scores(df, isolation_scores, dbscan_labels, statistical_anomalies)
        
        return results
    
    def get_anomaly_summary(self, results: pd.DataFrame) -> Dict:
        """Generate summary statistics for anomaly detection results."""
        summary = {
            'total_records': len(results),
            'anomalies_detected': len(results[results['risk_score'] >= 0.5]),
            'risk_level_counts': results['risk_level'].value_counts().to_dict(),
            'avg_risk_score': results['risk_score'].mean(),
            'high_risk_users': results[results['risk_score'] >= 0.7]['user_id'].nunique()
        }
        
        return summary
