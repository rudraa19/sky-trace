import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import io
import base64

class SecurityReportGenerator:
    """Generate comprehensive security reports and export data."""
    
    def __init__(self):
        self.report_templates = {
            'executive': self._generate_executive_summary,
            'technical': self._generate_technical_report,
            'incident': self._generate_incident_report
        }
    
    def generate_executive_summary(self, df: pd.DataFrame, analysis_results: Dict) -> str:
        """Generate executive summary report."""
        return self._generate_executive_summary(df, analysis_results)
    
    def _generate_executive_summary(self, df: pd.DataFrame, analysis_results: Dict) -> str:
        """Generate executive summary for management."""
        total_logins = len(df)
        high_risk_logins = len(df[df['risk_score'] >= 0.6])
        critical_logins = len(df[df['risk_score'] >= 0.8])
        unique_users = df['user_id'].nunique()
        high_risk_users = df[df['risk_score'] >= 0.7]['user_id'].nunique()
        
        date_range = f"{df['timestamp'].min().strftime('%Y-%m-%d')} to {df['timestamp'].max().strftime('%Y-%m-%d')}"
        
        # Calculate key metrics
        risk_percentage = (high_risk_logins / total_logins * 100) if total_logins > 0 else 0
        critical_percentage = (critical_logins / total_logins * 100) if total_logins > 0 else 0
        
        report = f"""
# EXECUTIVE SECURITY SUMMARY
## Analysis Period: {date_range}

### KEY FINDINGS

**Overall Security Status**: {'🔴 HIGH RISK' if critical_percentage > 5 else '🟡 MODERATE RISK' if risk_percentage > 10 else '🟢 LOW RISK'}

### CRITICAL METRICS
- **Total Login Events**: {total_logins:,}
- **High-Risk Events**: {high_risk_logins:,} ({risk_percentage:.1f}%)
- **Critical Events**: {critical_logins:,} ({critical_percentage:.1f}%)
- **Users Analyzed**: {unique_users:,}
- **High-Risk Users**: {high_risk_users:,}

### SECURITY THREATS DETECTED

"""
        
        # Add geographical analysis
        if 'geographical' in analysis_results:
            geo_analysis = analysis_results['geographical']
            if 'impossible_travel' in geo_analysis:
                impossible_travel = geo_analysis['impossible_travel']
                report += f"""
**Impossible Travel Incidents**: {impossible_travel.get('total_incidents', 0)}
- Affected Users: {impossible_travel.get('affected_users', 0)}
- Maximum Speed Detected: {impossible_travel.get('max_speed_detected', 0):.0f} km/h
"""
        
        # Add VPN/Proxy usage
        if 'vpn_usage' in analysis_results.get('geographical', {}):
            vpn_data = analysis_results['geographical']['vpn_usage']
            report += f"""
**VPN/Proxy Usage**:
- VPN Logins: {vpn_data.get('total_vpn_logins', 0)} ({vpn_data.get('vpn_percentage', 0):.1f}%)
- Proxy Logins: {vpn_data.get('total_proxy_logins', 0)}
"""
        
        # Recommendations
        report += """

### IMMEDIATE ACTIONS RECOMMENDED

"""
        
        if critical_percentage > 5:
            report += "🔴 **CRITICAL**: Immediate investigation required for critical risk events\n"
        if high_risk_users > 0:
            report += f"🟡 **HIGH**: Review {high_risk_users} users with elevated risk profiles\n"
        if 'impossible_travel' in analysis_results.get('geographical', {}):
            travel_incidents = analysis_results['geographical']['impossible_travel'].get('total_incidents', 0)
            if travel_incidents > 0:
                report += f"⚠️ **TRAVEL**: Investigate {travel_incidents} impossible travel incidents\n"
        
        report += """
### SECURITY POSTURE RECOMMENDATIONS

1. **Enhanced Monitoring**: Implement real-time alerting for critical risk events
2. **User Education**: Train users on secure login practices
3. **Access Controls**: Review and strengthen authentication mechanisms
4. **Geographical Restrictions**: Consider location-based access policies
5. **Regular Audits**: Schedule weekly security reviews

---
*Report generated on {current_time}*
""".format(current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        return report
    
    def _generate_technical_report(self, df: pd.DataFrame, analysis_results: Dict) -> str:
        """Generate detailed technical report."""
        report = f"""
# TECHNICAL SECURITY ANALYSIS REPORT
## Analysis Period: {df['timestamp'].min()} to {df['timestamp'].max()}

### DETECTION METHODOLOGY

**Machine Learning Models Used**:
- Isolation Forest (Contamination: 10%)
- DBSCAN Clustering (eps=0.5, min_samples=5)
- Statistical Rule-Based Detection

**Risk Scoring Algorithm**:
- Isolation Forest Score: 40% weight
- DBSCAN Outlier Detection: 30% weight
- Statistical Anomalies: 30% weight
- Final Score Range: 0.0 (low risk) to 1.0 (critical risk)

### DETAILED FINDINGS

**Risk Distribution**:
"""
        
        # Risk level breakdown
        risk_counts = df['risk_level'].value_counts()
        for level, count in risk_counts.items():
            percentage = (count / len(df) * 100)
            report += f"- {level}: {count:,} events ({percentage:.1f}%)\n"
        
        # Statistical anomalies
        report += "\n**Statistical Anomalies Detected**:\n"
        stat_cols = [col for col in df.columns if col.startswith('is_')]
        for col in stat_cols:
            if col in df.columns:
                count = df[col].sum()
                anomaly_type = col.replace('is_', '').replace('_', ' ').title()
                report += f"- {anomaly_type}: {count:,} incidents\n"
        
        # Top risk users
        report += "\n**Top 10 High-Risk Users**:\n"
        user_risk = df.groupby('user_id')['risk_score'].agg(['mean', 'max', 'count']).sort_values('mean', ascending=False).head(10)
        for user_id, stats in user_risk.iterrows():
            report += f"- {user_id}: Avg Risk {stats['mean']:.3f}, Max Risk {stats['max']:.3f}, Events {stats['count']}\n"
        
        # Geographical analysis
        if 'geographical' in analysis_results:
            geo_analysis = analysis_results['geographical']
            report += f"""

### GEOGRAPHICAL ANALYSIS

**Location Diversity**:
- Unique Countries: {geo_analysis.get('unique_countries', 0)}
- Unique Cities: {geo_analysis.get('unique_cities', 0)}

**Top Countries by Login Volume**:
"""
            for country, count in list(geo_analysis.get('countries', {}).items())[:5]:
                report += f"- {country}: {count:,} logins\n"
        
        # Device analysis
        if 'browser' in df.columns and 'os' in df.columns:
            report += """

### DEVICE ANALYSIS

**Browser Distribution**:
"""
            browser_counts = df['browser'].value_counts().head(5)
            for browser, count in browser_counts.items():
                percentage = (count / len(df) * 100)
                report += f"- {browser}: {count:,} ({percentage:.1f}%)\n"
            
            report += "\n**Operating System Distribution**:\n"
            os_counts = df['os'].value_counts().head(5)
            for os_name, count in os_counts.items():
                percentage = (count / len(df) * 100)
                report += f"- {os_name}: {count:,} ({percentage:.1f}%)\n"
        
        report += f"""

### TECHNICAL RECOMMENDATIONS

**Model Performance**:
- Isolation Forest effectively identified {df['isolation_score'].quantile(0.9):.3f} as 90th percentile threshold
- DBSCAN identified {(df.get('is_dbscan_outlier', pd.Series([0])).sum())} outlier events
- Statistical rules captured {sum(df[col].sum() for col in stat_cols if col in df.columns)} anomalous patterns

**Tuning Recommendations**:
1. Adjust risk threshold based on organizational tolerance
2. Enhance geographical rules for specific business locations
3. Implement user behavior baselines for improved personalization
4. Consider time-series analysis for temporal pattern detection

**Integration Points**:
- SIEM System: Export alerts for high-risk events
- Identity Management: Flag users with persistent high-risk scores
- Network Security: Correlate with firewall and VPN logs
- Incident Response: Automate ticket creation for critical events

---
*Technical analysis completed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        return report
    
    def _generate_incident_report(self, df: pd.DataFrame, analysis_results: Dict) -> str:
        """Generate incident-specific report."""
        critical_events = df[df['risk_level'] == 'Critical']
        high_events = df[df['risk_level'] == 'High']
        
        report = f"""
# SECURITY INCIDENT REPORT
## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

### INCIDENT SUMMARY

**Critical Incidents**: {len(critical_events)}
**High-Risk Incidents**: {len(high_events)}
**Total Incidents Requiring Review**: {len(critical_events) + len(high_events)}

### CRITICAL INCIDENTS (Risk Score ≥ 0.8)

"""
        
        if len(critical_events) > 0:
            for idx, incident in critical_events.head(20).iterrows():
                report += f"""
**Incident #{idx}**
- User: {incident['user_id']}
- Time: {incident['timestamp']}
- IP: {incident['ip_address']}
- Location: {incident.get('city', 'Unknown')}, {incident.get('country', 'Unknown')}
- Risk Score: {incident['risk_score']:.3f}
- Browser: {incident.get('browser', 'Unknown')}
- OS: {incident.get('os', 'Unknown')}
"""
                
                # Add specific anomaly flags
                anomaly_flags = []
                if incident.get('is_unusual_hours', False):
                    anomaly_flags.append("Unusual Hours")
                if incident.get('is_weekend_login', False):
                    anomaly_flags.append("Weekend Login")
                if incident.get('impossible_travel', False):
                    anomaly_flags.append(f"Impossible Travel ({incident.get('travel_speed_kmh', 0):.0f} km/h)")
                if incident.get('is_multiple_browsers', False):
                    anomaly_flags.append("Multiple Browsers")
                if incident.get('is_vpn', False):
                    anomaly_flags.append("VPN Usage")
                
                if anomaly_flags:
                    report += f"- Anomaly Flags: {', '.join(anomaly_flags)}\n"
                
                report += "\n"
        else:
            report += "No critical incidents detected.\n"
        
        # Investigation recommendations
        report += """
### INVESTIGATION RECOMMENDATIONS

**Immediate Actions**:
1. Review all critical incidents for potential account compromise
2. Contact affected users to verify legitimate access
3. Implement additional authentication for high-risk users
4. Monitor for continued suspicious activity

**Follow-up Actions**:
1. Analyze user behavior patterns for baseline establishment
2. Review geographical access policies
3. Enhance monitoring for identified risk indicators
4. Update incident response procedures based on findings

### INCIDENT TRACKING

Use the following incident IDs for tracking and follow-up:
"""
        
        for idx, incident in critical_events.head(10).iterrows():
            incident_id = f"SEC-{datetime.now().strftime('%Y%m%d')}-{idx:04d}"
            report += f"- {incident_id}: {incident['user_id']} at {incident['timestamp']}\n"
        
        return report
    
    def export_anomaly_data(self, df: pd.DataFrame, format_type: str = 'csv') -> bytes:
        """Export anomaly data in specified format."""
        if format_type.lower() == 'csv':
            # Select relevant columns for export
            export_columns = [
                'timestamp', 'user_id', 'ip_address', 'risk_score', 'risk_level',
                'city', 'country', 'browser', 'os'
            ]
            
            # Add anomaly flags
            anomaly_columns = [col for col in df.columns if col.startswith('is_')]
            export_columns.extend(anomaly_columns)
            
            # Filter to only existing columns
            available_columns = [col for col in export_columns if col in df.columns]
            
            export_df = df[available_columns].copy()
            
            # Convert to CSV
            csv_buffer = io.StringIO()
            export_df.to_csv(csv_buffer, index=False)
            return csv_buffer.getvalue().encode('utf-8')
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def create_downloadable_report(self, report_content: str, filename: str) -> str:
        """Create downloadable link for report."""
        b64 = base64.b64encode(report_content.encode()).decode()
        return f'<a href="data:text/plain;base64,{b64}" download="{filename}">Download {filename}</a>'
    
    def get_alert_configuration(self) -> Dict:
        """Get recommended alert configuration."""
        return {
            'risk_thresholds': {
                'low': 0.0,
                'medium': 0.4,
                'high': 0.6,
                'critical': 0.8
            },
            'alert_conditions': {
                'immediate': ['risk_level == "Critical"'],
                'hourly': ['risk_level == "High"'],
                'daily': ['risk_level == "Medium"']
            },
            'notification_channels': {
                'email': 'security-team@company.com',
                'slack': '#security-alerts',
                'sms': '+1-555-SECURITY'
            }
        }
    
    def generate_scheduled_report_summary(self, df: pd.DataFrame) -> Dict:
        """Generate summary for scheduled reports."""
        now = datetime.now()
        last_24h = df[df['timestamp'] >= (now - timedelta(hours=24))]
        last_week = df[df['timestamp'] >= (now - timedelta(days=7))]
        
        summary = {
            'report_timestamp': now.isoformat(),
            'last_24_hours': {
                'total_logins': len(last_24h),
                'high_risk_events': len(last_24h[last_24h['risk_score'] >= 0.6]),
                'critical_events': len(last_24h[last_24h['risk_score'] >= 0.8]),
                'unique_users': last_24h['user_id'].nunique()
            },
            'last_week': {
                'total_logins': len(last_week),
                'high_risk_events': len(last_week[last_week['risk_score'] >= 0.6]),
                'critical_events': len(last_week[last_week['risk_score'] >= 0.8]),
                'unique_users': last_week['user_id'].nunique()
            },
            'trends': {
                'risk_score_trend': 'increasing' if last_24h['risk_score'].mean() > last_week['risk_score'].mean() else 'decreasing',
                'activity_trend': 'increasing' if len(last_24h) > (len(last_week) / 7) else 'decreasing'
            }
        }
        
        return summary
