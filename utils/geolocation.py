import pandas as pd
import numpy as np
import requests
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import streamlit as st
import time

class GeolocationAnalyzer:
    """Handles IP geolocation and travel analysis for login security."""
    
    def __init__(self):
        self.location_cache = {}
        self.earth_radius_km = 6371  # Earth's radius in kilometers
        
    def get_ip_location(self, ip_address: str) -> Dict:
        """
        Get geographical location for an IP address.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Dictionary with location information
        """
        # Check cache first
        if ip_address in self.location_cache:
            return self.location_cache[ip_address]
        
        # Default response for invalid/private IPs
        default_location = {
            'ip': ip_address,
            'country': 'Unknown',
            'country_code': 'XX',
            'region': 'Unknown',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'isp': 'Unknown',
            'timezone': 'UTC',
            'is_proxy': False,
            'is_vpn': False
        }
        
        # Skip private IP ranges
        if self._is_private_ip(ip_address):
            self.location_cache[ip_address] = default_location
            return default_location
        
        try:
            # Using ip-api.com (free tier allows 1000 requests per hour)
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                timeout=5,
                params={'fields': 'status,country,countryCode,region,city,lat,lon,isp,timezone,proxy,mobile'}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    location = {
                        'ip': ip_address,
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'XX'),
                        'region': data.get('region', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'latitude': float(data.get('lat', 0.0)),
                        'longitude': float(data.get('lon', 0.0)),
                        'isp': data.get('isp', 'Unknown'),
                        'timezone': data.get('timezone', 'UTC'),
                        'is_proxy': data.get('proxy', False),
                        'is_vpn': 'VPN' in data.get('isp', '').upper() or 'PROXY' in data.get('isp', '').upper()
                    }
                    
                    self.location_cache[ip_address] = location
                    return location
            
            # Rate limiting - wait before retry
            time.sleep(0.1)
            
        except Exception as e:
            st.warning(f"Failed to get location for {ip_address}: {str(e)}")
        
        # Return default on failure
        self.location_cache[ip_address] = default_location
        return default_location
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private ranges."""
        try:
            parts = [int(x) for x in ip.split('.')]
            
            # Private IP ranges
            if parts[0] == 10:
                return True
            elif parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            elif parts[0] == 192 and parts[1] == 168:
                return True
            elif parts[0] == 127:  # Localhost
                return True
                
            return False
        except:
            return True
    
    def enrich_with_geolocation(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add geolocation information to login data.
        
        Args:
            df: DataFrame with IP addresses
            
        Returns:
            DataFrame enriched with location data
        """
        enriched_df = df.copy()
        
        # Get unique IPs to minimize API calls
        unique_ips = df['ip_address'].unique()
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        location_data = []
        for i, ip in enumerate(unique_ips):
            status_text.text(f'Getting location for IP {i+1}/{len(unique_ips)}: {ip}')
            location = self.get_ip_location(ip)
            location_data.append(location)
            
            progress_bar.progress((i + 1) / len(unique_ips))
            
            # Rate limiting to respect API limits
            if i < len(unique_ips) - 1:
                time.sleep(0.1)
        
        # Create location DataFrame
        location_df = pd.DataFrame(location_data)
        
        # Merge with original data
        enriched_df = enriched_df.merge(
            location_df,
            left_on='ip_address',
            right_on='ip',
            how='left'
        )
        
        progress_bar.empty()
        status_text.empty()
        
        return enriched_df
    
    def calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate distance between two points using Haversine formula.
        
        Args:
            lat1, lon1: Coordinates of first point
            lat2, lon2: Coordinates of second point
            
        Returns:
            Distance in kilometers
        """
        # Convert to radians
        lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
        
        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = np.sin(dlat/2)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon/2)**2
        c = 2 * np.arcsin(np.sqrt(a))
        
        return self.earth_radius_km * c
    
    def detect_impossible_travel(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect impossible travel based on geographical distance and time.
        
        Args:
            df: DataFrame with geolocation data
            
        Returns:
            DataFrame with impossible travel indicators
        """
        travel_df = df.copy()
        travel_df['impossible_travel'] = False
        travel_df['travel_speed_kmh'] = 0.0
        travel_df['distance_km'] = 0.0
        travel_df['time_diff_hours'] = 0.0
        
        # Sort by user and timestamp
        travel_df = travel_df.sort_values(['user_id', 'timestamp'])
        
        # Maximum realistic travel speed (including commercial flights)
        max_speed_kmh = 1000  # km/h
        
        for user_id in travel_df['user_id'].unique():
            user_data = travel_df[travel_df['user_id'] == user_id].copy()
            
            if len(user_data) < 2:
                continue
            
            for i in range(1, len(user_data)):
                prev_idx = user_data.iloc[i-1].name
                curr_idx = user_data.iloc[i].name
                
                prev_location = user_data.iloc[i-1]
                curr_location = user_data.iloc[i]
                
                # Skip if same location
                if (prev_location['latitude'] == curr_location['latitude'] and 
                    prev_location['longitude'] == curr_location['longitude']):
                    continue
                
                # Calculate distance
                distance = self.calculate_distance(
                    prev_location['latitude'], prev_location['longitude'],
                    curr_location['latitude'], curr_location['longitude']
                )
                
                # Calculate time difference
                time_diff = curr_location['timestamp'] - prev_location['timestamp']
                time_diff_hours = time_diff.total_seconds() / 3600
                
                # Avoid division by zero
                if time_diff_hours <= 0:
                    continue
                
                # Calculate required speed
                required_speed = distance / time_diff_hours
                
                # Update travel metrics
                travel_df.loc[curr_idx, 'distance_km'] = distance
                travel_df.loc[curr_idx, 'time_diff_hours'] = time_diff_hours
                travel_df.loc[curr_idx, 'travel_speed_kmh'] = required_speed
                
                # Flag impossible travel
                if required_speed > max_speed_kmh:
                    travel_df.loc[curr_idx, 'impossible_travel'] = True
        
        return travel_df
    
    def analyze_geographical_patterns(self, df: pd.DataFrame) -> Dict:
        """
        Analyze geographical patterns in login data.
        
        Args:
            df: DataFrame with geolocation data
            
        Returns:
            Dictionary with geographical analysis results
        """
        analysis = {}
        
        # Country distribution
        analysis['countries'] = df['country'].value_counts().to_dict()
        analysis['unique_countries'] = df['country'].nunique()
        
        # City distribution
        analysis['cities'] = df['city'].value_counts().head(10).to_dict()
        analysis['unique_cities'] = df['city'].nunique()
        
        # VPN/Proxy usage
        analysis['vpn_usage'] = {
            'total_vpn_logins': df['is_vpn'].sum() if 'is_vpn' in df.columns else 0,
            'total_proxy_logins': df['is_proxy'].sum() if 'is_proxy' in df.columns else 0,
            'vpn_percentage': (df['is_vpn'].mean() * 100) if 'is_vpn' in df.columns else 0
        }
        
        # Impossible travel incidents
        if 'impossible_travel' in df.columns:
            analysis['impossible_travel'] = {
                'total_incidents': df['impossible_travel'].sum(),
                'affected_users': df[df['impossible_travel']]['user_id'].nunique(),
                'max_speed_detected': df['travel_speed_kmh'].max(),
                'avg_impossible_distance': df[df['impossible_travel']]['distance_km'].mean()
            }
        
        # Risk by geography
        if 'risk_score' in df.columns:
            country_risk = df.groupby('country')['risk_score'].agg(['mean', 'count']).round(3)
            analysis['country_risk'] = country_risk.to_dict('index')
        
        return analysis
    
    def get_location_clusters(self, df: pd.DataFrame) -> List[Dict]:
        """
        Identify geographical clusters of login activity.
        
        Args:
            df: DataFrame with geolocation data
            
        Returns:
            List of location clusters with statistics
        """
        from sklearn.cluster import DBSCAN
        
        # Filter out unknown locations
        valid_locations = df[(df['latitude'] != 0) & (df['longitude'] != 0)].copy()
        
        if len(valid_locations) < 2:
            return []
        
        # Prepare coordinates for clustering
        coordinates = valid_locations[['latitude', 'longitude']].values
        
        # DBSCAN clustering (eps in degrees, roughly 50km at equator)
        clustering = DBSCAN(eps=0.5, min_samples=2).fit(coordinates)
        valid_locations['cluster'] = clustering.labels_
        
        clusters = []
        for cluster_id in set(clustering.labels_):
            if cluster_id == -1:  # Skip noise points
                continue
            
            cluster_data = valid_locations[valid_locations['cluster'] == cluster_id]
            
            cluster_info = {
                'cluster_id': cluster_id,
                'center_lat': cluster_data['latitude'].mean(),
                'center_lon': cluster_data['longitude'].mean(),
                'login_count': len(cluster_data),
                'unique_users': cluster_data['user_id'].nunique(),
                'countries': list(cluster_data['country'].unique()),
                'cities': list(cluster_data['city'].unique()),
                'avg_risk_score': cluster_data['risk_score'].mean() if 'risk_score' in cluster_data.columns else 0
            }
            
            clusters.append(cluster_info)
        
        return sorted(clusters, key=lambda x: x['login_count'], reverse=True)
