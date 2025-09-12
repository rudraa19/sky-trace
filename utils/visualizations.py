import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
import folium
from folium import plugins
import streamlit as st
from typing import Dict, List, Optional

class SecurityVisualizations:
    """Create interactive visualizations for security analysis."""
    
    def __init__(self):
        self.color_scheme = {
            'low': '#2E8B57',      # Sea Green
            'medium': '#FFD700',    # Gold
            'high': '#FF6347',      # Tomato
            'critical': '#DC143C'   # Crimson
        }
    
    def create_risk_distribution_chart(self, df: pd.DataFrame) -> go.Figure:
        """Create risk score distribution chart."""
        fig = px.histogram(
            df, 
            x='risk_score',
            nbins=20,
            title='Risk Score Distribution',
            labels={'risk_score': 'Risk Score', 'count': 'Number of Logins'},
            color_discrete_sequence=['#1f77b4']
        )
        
        # Add threshold lines
        fig.add_vline(x=0.4, line_dash="dash", line_color="orange", 
                     annotation_text="Medium Risk")
        fig.add_vline(x=0.6, line_dash="dash", line_color="red", 
                     annotation_text="High Risk")
        fig.add_vline(x=0.8, line_dash="dash", line_color="darkred", 
                     annotation_text="Critical Risk")
        
        fig.update_layout(height=400)
        return fig
    
    def create_risk_level_pie_chart(self, df: pd.DataFrame) -> go.Figure:
        """Create pie chart of risk levels."""
        risk_counts = df['risk_level'].value_counts()
        
        colors = [self.color_scheme.get(level.lower(), '#808080') for level in risk_counts.index]
        
        fig = px.pie(
            values=risk_counts.values,
            names=risk_counts.index,
            title='Risk Level Distribution',
            color_discrete_sequence=colors
        )
        
        fig.update_layout(height=400)
        return fig
    
    def create_time_series_chart(self, df: pd.DataFrame) -> go.Figure:
        """Create time series chart of login activity."""
        # Resample data by hour
        df_hourly = df.set_index('timestamp').resample('H').agg({
            'user_id': 'count',
            'risk_score': 'mean'
        }).reset_index()
        
        # Create subplot with secondary y-axis
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        
        # Add login count
        fig.add_trace(
            go.Scatter(
                x=df_hourly['timestamp'],
                y=df_hourly['user_id'],
                name='Login Count',
                line=dict(color='#1f77b4')
            ),
            secondary_y=False
        )
        
        # Add average risk score
        fig.add_trace(
            go.Scatter(
                x=df_hourly['timestamp'],
                y=df_hourly['risk_score'],
                name='Avg Risk Score',
                line=dict(color='#ff7f0e')
            ),
            secondary_y=True
        )
        
        # Update layout
        fig.update_xaxes(title_text="Time")
        fig.update_yaxes(title_text="Login Count", secondary_y=False)
        fig.update_yaxes(title_text="Average Risk Score", secondary_y=True)
        
        fig.update_layout(
            title='Login Activity Over Time',
            height=400
        )
        
        return fig
    
    def create_geographical_heatmap(self, df: pd.DataFrame) -> go.Figure:
        """Create geographical heatmap of login locations."""
        # Filter valid coordinates
        valid_coords = df[(df['latitude'] != 0) & (df['longitude'] != 0)]
        
        if len(valid_coords) == 0:
            # Return empty map
            fig = go.Figure()
            fig.add_annotation(
                text="No geographical data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
            return fig
        
        # Aggregate by location
        location_stats = valid_coords.groupby(['latitude', 'longitude']).agg({
            'user_id': 'count',
            'risk_score': 'mean',
            'city': 'first',
            'country': 'first'
        }).reset_index()
        
        # Create scatter plot on map
        fig = px.scatter_mapbox(
            location_stats,
            lat='latitude',
            lon='longitude',
            size='user_id',
            color='risk_score',
            hover_data=['city', 'country'],
            color_continuous_scale='Reds',
            size_max=20,
            zoom=1,
            title='Login Locations and Risk Levels'
        )
        
        fig.update_layout(
            mapbox_style="open-street-map",
            height=500
        )
        
        return fig
    
    def create_user_risk_chart(self, df: pd.DataFrame, top_n: int = 20) -> go.Figure:
        """Create chart of users with highest risk scores."""
        user_risk = df.groupby('user_id')['risk_score'].agg(['mean', 'max', 'count']).reset_index()
        user_risk = user_risk.sort_values('mean', ascending=False).head(top_n)
        
        fig = go.Figure()
        
        # Add average risk score bars
        fig.add_trace(go.Bar(
            x=user_risk['user_id'],
            y=user_risk['mean'],
            name='Average Risk',
            marker_color='orange',
            opacity=0.7
        ))
        
        # Add maximum risk score line
        fig.add_trace(go.Scatter(
            x=user_risk['user_id'],
            y=user_risk['max'],
            mode='lines+markers',
            name='Maximum Risk',
            line=dict(color='red', width=2)
        ))
        
        fig.update_layout(
            title=f'Top {top_n} Users by Risk Score',
            xaxis_title='User ID',
            yaxis_title='Risk Score',
            height=400
        )
        
        return fig
    
    def create_anomaly_timeline(self, df: pd.DataFrame, risk_threshold: float = 0.7) -> go.Figure:
        """Create timeline of anomalous events."""
        anomalies = df[df['risk_score'] >= risk_threshold].copy()
        
        if len(anomalies) == 0:
            fig = go.Figure()
            fig.add_annotation(
                text="No anomalies detected above threshold",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
            return fig
        
        # Create timeline scatter plot
        fig = px.scatter(
            anomalies,
            x='timestamp',
            y='user_id',
            color='risk_score',
            size='risk_score',
            hover_data=['ip_address', 'city', 'country'],
            color_continuous_scale='Reds',
            title='Anomaly Timeline'
        )
        
        fig.update_layout(
            height=400,
            xaxis_title='Time',
            yaxis_title='User ID'
        )
        
        return fig
    
    def create_device_analysis_chart(self, df: pd.DataFrame) -> go.Figure:
        """Create chart analyzing device patterns."""
        if 'browser' not in df.columns or 'os' not in df.columns:
            fig = go.Figure()
            fig.add_annotation(
                text="Device data not available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
            return fig
        
        # Create sunburst chart
        device_data = df.groupby(['os', 'browser']).agg({
            'user_id': 'count',
            'risk_score': 'mean'
        }).reset_index()
        
        fig = px.sunburst(
            device_data,
            path=['os', 'browser'],
            values='user_id',
            color='risk_score',
            color_continuous_scale='RdYlBu_r',
            title='Device Usage Patterns'
        )
        
        fig.update_layout(height=500)
        return fig
    
    def create_folium_map(self, df: pd.DataFrame) -> folium.Map:
        """Create interactive Folium map with login locations."""
        # Filter valid coordinates
        valid_coords = df[(df['latitude'] != 0) & (df['longitude'] != 0)]
        
        if len(valid_coords) == 0:
            # Return basic world map
            return folium.Map(location=[0, 0], zoom_start=2)
        
        # Calculate map center
        center_lat = valid_coords['latitude'].mean()
        center_lon = valid_coords['longitude'].mean()
        
        # Create map
        m = folium.Map(
            location=[center_lat, center_lon],
            zoom_start=2,
            tiles='OpenStreetMap'
        )
        
        # Add markers for each login
        for _, row in valid_coords.iterrows():
            # Color based on risk level
            if row['risk_score'] >= 0.8:
                color = 'red'
                icon = 'exclamation-sign'
            elif row['risk_score'] >= 0.6:
                color = 'orange'
                icon = 'warning-sign'
            elif row['risk_score'] >= 0.4:
                color = 'yellow'
                icon = 'info-sign'
            else:
                color = 'green'
                icon = 'ok-sign'
            
            # Create popup text
            popup_text = f"""
            <b>User:</b> {row['user_id']}<br>
            <b>Location:</b> {row.get('city', 'Unknown')}, {row.get('country', 'Unknown')}<br>
            <b>IP:</b> {row['ip_address']}<br>
            <b>Risk Score:</b> {row['risk_score']:.3f}<br>
            <b>Time:</b> {row['timestamp']}<br>
            """
            
            if 'impossible_travel' in row and row['impossible_travel']:
                popup_text += f"<b>⚠️ Impossible Travel Detected</b><br>"
                popup_text += f"<b>Speed:</b> {row.get('travel_speed_kmh', 0):.1f} km/h<br>"
            
            folium.Marker(
                location=[row['latitude'], row['longitude']],
                popup=folium.Popup(popup_text, max_width=300),
                icon=folium.Icon(color=color, icon=icon)
            ).add_to(m)
        
        # Add heatmap layer
        if len(valid_coords) > 1:
            heat_data = [[row['latitude'], row['longitude'], row['risk_score']] 
                        for _, row in valid_coords.iterrows()]
            
            plugins.HeatMap(
                heat_data,
                name='Risk Heatmap',
                radius=15,
                blur=10,
                max_zoom=1
            ).add_to(m)
        
        # Add layer control
        folium.LayerControl().add_to(m)
        
        return m
    
    def create_impossible_travel_chart(self, df: pd.DataFrame) -> go.Figure:
        """Create chart showing impossible travel incidents."""
        if 'impossible_travel' not in df.columns:
            fig = go.Figure()
            fig.add_annotation(
                text="Impossible travel analysis not available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
            return fig
        
        impossible_travel = df[df['impossible_travel'] == True]
        
        if len(impossible_travel) == 0:
            fig = go.Figure()
            fig.add_annotation(
                text="No impossible travel incidents detected",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
            return fig
        
        fig = px.scatter(
            impossible_travel,
            x='time_diff_hours',
            y='distance_km',
            color='travel_speed_kmh',
            size='risk_score',
            hover_data=['user_id', 'city', 'country'],
            title='Impossible Travel Incidents',
            labels={
                'time_diff_hours': 'Time Difference (hours)',
                'distance_km': 'Distance (km)',
                'travel_speed_kmh': 'Required Speed (km/h)'
            },
            color_continuous_scale='Reds'
        )
        
        # Add maximum realistic speed line
        max_time = impossible_travel['time_diff_hours'].max()
        max_realistic_speed = 1000  # km/h
        
        fig.add_trace(go.Scatter(
            x=[0, max_time],
            y=[0, max_time * max_realistic_speed],
            mode='lines',
            name='Max Realistic Speed (1000 km/h)',
            line=dict(dash='dash', color='red')
        ))
        
        fig.update_layout(height=400)
        return fig
