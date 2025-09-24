"""
Chart Generator - Chart and Visualization Generation Service

This service generates various types of charts and visualizations
for reports and dashboards.
"""

from typing import Dict, List, Optional, Any, Union
import base64
import io
from datetime import datetime

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

logger = get_logger(__name__)
metrics = get_metrics()


class ChartGenerator:
    """
    Chart generation service for creating various types of visualizations.
    
    This generator:
    1. Creates interactive charts using Plotly
    2. Supports multiple chart types (bar, line, pie, scatter, etc.)
    3. Generates static images for reports
    4. Provides customizable styling and themes
    """
    
    def __init__(self):
        # Default chart configuration
        self.default_config = {
            "displayModeBar": False,
            "staticPlot": False,
            "responsive": True
        }
        
        # Color palettes
        self.color_palettes = {
            "security": ["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4", "#FFEAA7"],
            "risk": ["#E74C3C", "#E67E22", "#F39C12", "#F1C40F", "#2ECC71"],
            "status": ["#27AE60", "#3498DB", "#9B59B6", "#E67E22", "#E74C3C"],
            "default": ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]
        }
        
        logger.info("Chart generator initialized")
    
    @traced("chart_generator_create_pie_chart")
    async def create_pie_chart(
        self,
        data: Dict[str, Any],
        title: str,
        labels: Optional[List[str]] = None,
        colors: Optional[List[str]] = None,
        theme: str = "default"
    ) -> Dict[str, Any]:
        """Create a pie chart."""
        try:
            # Extract data
            if isinstance(data, dict):
                labels = labels or list(data.keys())
                values = list(data.values())
            else:
                raise ValueError("Data must be a dictionary")
            
            # Create figure
            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                hole=0.3,
                textinfo='label+percent',
                textposition='outside',
                marker_colors=colors or self.color_palettes.get(theme, self.color_palettes["default"])
            )])
            
            # Update layout
            fig.update_layout(
                title=title,
                showlegend=True,
                font=dict(size=12),
                margin=dict(t=50, b=50, l=50, r=50)
            )
            
            # Convert to JSON and image
            chart_json = fig.to_json()
            chart_image = self._fig_to_base64(fig)
            
            return {
                "type": "pie",
                "title": title,
                "data": chart_json,
                "image": chart_image,
                "config": self.default_config
            }
            
        except Exception as e:
            logger.error(f"Error creating pie chart: {e}")
            raise
    
    @traced("chart_generator_create_bar_chart")
    async def create_bar_chart(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]]],
        title: str,
        x_label: str = "Category",
        y_label: str = "Value",
        orientation: str = "vertical",
        colors: Optional[List[str]] = None,
        theme: str = "default"
    ) -> Dict[str, Any]:
        """Create a bar chart."""
        try:
            # Convert data to DataFrame
            if isinstance(data, dict):
                df = pd.DataFrame(list(data.items()), columns=[x_label, y_label])
            elif isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                raise ValueError("Data must be a dictionary or list of dictionaries")
            
            # Create figure
            if orientation == "horizontal":
                fig = px.bar(
                    df,
                    x=y_label,
                    y=x_label,
                    orientation='h',
                    title=title,
                    color_discrete_sequence=colors or self.color_palettes.get(theme, self.color_palettes["default"])
                )
            else:
                fig = px.bar(
                    df,
                    x=x_label,
                    y=y_label,
                    title=title,
                    color_discrete_sequence=colors or self.color_palettes.get(theme, self.color_palettes["default"])
                )
            
            # Update layout
            fig.update_layout(
                xaxis_title=x_label,
                yaxis_title=y_label,
                showlegend=False,
                font=dict(size=12),
                margin=dict(t=50, b=50, l=50, r=50)
            )
            
            # Convert to JSON and image
            chart_json = fig.to_json()
            chart_image = self._fig_to_base64(fig)
            
            return {
                "type": "bar",
                "title": title,
                "data": chart_json,
                "image": chart_image,
                "config": self.default_config
            }
            
        except Exception as e:
            logger.error(f"Error creating bar chart: {e}")
            raise
    
    @traced("chart_generator_create_line_chart")
    async def create_line_chart(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]]],
        title: str,
        x_label: str = "Time",
        y_label: str = "Value",
        multiple_series: bool = False,
        colors: Optional[List[str]] = None,
        theme: str = "default"
    ) -> Dict[str, Any]:
        """Create a line chart."""
        try:
            # Convert data to DataFrame
            if isinstance(data, dict):
                df = pd.DataFrame(list(data.items()), columns=[x_label, y_label])
            elif isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                raise ValueError("Data must be a dictionary or list of dictionaries")
            
            # Create figure
            if multiple_series and len(df.columns) > 2:
                fig = go.Figure()
                for i, column in enumerate(df.columns[1:]):
                    fig.add_trace(go.Scatter(
                        x=df[df.columns[0]],
                        y=df[column],
                        mode='lines+markers',
                        name=column,
                        line=dict(
                            color=colors[i] if colors and i < len(colors) else self.color_palettes.get(theme, self.color_palettes["default"])[i % len(self.color_palettes.get(theme, self.color_palettes["default"]))]
                        )
                    ))
            else:
                fig = px.line(
                    df,
                    x=df.columns[0],
                    y=df.columns[1],
                    title=title,
                    color_discrete_sequence=colors or self.color_palettes.get(theme, self.color_palettes["default"])
                )
            
            # Update layout
            fig.update_layout(
                title=title,
                xaxis_title=x_label,
                yaxis_title=y_label,
                showlegend=multiple_series,
                font=dict(size=12),
                margin=dict(t=50, b=50, l=50, r=50)
            )
            
            # Convert to JSON and image
            chart_json = fig.to_json()
            chart_image = self._fig_to_base64(fig)
            
            return {
                "type": "line",
                "title": title,
                "data": chart_json,
                "image": chart_image,
                "config": self.default_config
            }
            
        except Exception as e:
            logger.error(f"Error creating line chart: {e}")
            raise
    
    @traced("chart_generator_create_scatter_plot")
    async def create_scatter_plot(
        self,
        data: List[Dict[str, Any]],
        title: str,
        x_label: str = "X",
        y_label: str = "Y",
        size_column: Optional[str] = None,
        color_column: Optional[str] = None,
        theme: str = "default"
    ) -> Dict[str, Any]:
        """Create a scatter plot."""
        try:
            # Convert data to DataFrame
            df = pd.DataFrame(data)
            
            # Create figure
            fig = px.scatter(
                df,
                x=x_label,
                y=y_label,
                size=size_column,
                color=color_column,
                title=title,
                color_discrete_sequence=self.color_palettes.get(theme, self.color_palettes["default"])
            )
            
            # Update layout
            fig.update_layout(
                showlegend=bool(color_column),
                font=dict(size=12),
                margin=dict(t=50, b=50, l=50, r=50)
            )
            
            # Convert to JSON and image
            chart_json = fig.to_json()
            chart_image = self._fig_to_base64(fig)
            
            return {
                "type": "scatter",
                "title": title,
                "data": chart_json,
                "image": chart_image,
                "config": self.default_config
            }
            
        except Exception as e:
            logger.error(f"Error creating scatter plot: {e}")
            raise
    
    @traced("chart_generator_create_heatmap")
    async def create_heatmap(
        self,
        data: List[List[float]],
        title: str,
        x_labels: List[str],
        y_labels: List[str],
        colorscale: str = "Viridis",
        theme: str = "default"
    ) -> Dict[str, Any]:
        """Create a heatmap."""
        try:
            # Create figure
            fig = go.Figure(data=go.Heatmap(
                z=data,
                x=x_labels,
                y=y_labels,
                colorscale=colorscale,
                showscale=True
            ))
            
            # Update layout
            fig.update_layout(
                title=title,
                font=dict(size=12),
                margin=dict(t=50, b=50, l=50, r=50)
            )
            
            # Convert to JSON and image
            chart_json = fig.to_json()
            chart_image = self._fig_to_base64(fig)
            
            return {
                "type": "heatmap",
                "title": title,
                "data": chart_json,
                "image": chart_image,
                "config": self.default_config
            }
            
        except Exception as e:
            logger.error(f"Error creating heatmap: {e}")
            raise
    
    @traced("chart_generator_create_gauge_chart")
    async def create_gauge_chart(
        self,
        value: float,
        title: str,
        min_value: float = 0,
        max_value: float = 100,
        threshold_ranges: Optional[List[Dict[str, Any]]] = None,
        theme: str = "default"
    ) -> Dict[str, Any]:
        """Create a gauge chart."""
        try:
            # Default threshold ranges
            if threshold_ranges is None:
                threshold_ranges = [
                    {"range": [0, 30], "color": "#E74C3C"},
                    {"range": [30, 70], "color": "#F39C12"},
                    {"range": [70, 100], "color": "#27AE60"}
                ]
            
            # Create figure
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=value,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': title},
                gauge={
                    'axis': {'range': [min_value, max_value]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [r["range"][0], r["range"][1]], 'color': r["color"]}
                        for r in threshold_ranges
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': max_value * 0.9
                    }
                }
            ))
            
            # Update layout
            fig.update_layout(
                font=dict(size=12),
                margin=dict(t=50, b=50, l=50, r=50)
            )
            
            # Convert to JSON and image
            chart_json = fig.to_json()
            chart_image = self._fig_to_base64(fig)
            
            return {
                "type": "gauge",
                "title": title,
                "data": chart_json,
                "image": chart_image,
                "config": self.default_config
            }
            
        except Exception as e:
            logger.error(f"Error creating gauge chart: {e}")
            raise
    
    @traced("chart_generator_create_histogram")
    async def create_histogram(
        self,
        data: List[float],
        title: str,
        x_label: str = "Value",
        y_label: str = "Frequency",
        bins: int = 20,
        colors: Optional[List[str]] = None,
        theme: str = "default"
    ) -> Dict[str, Any]:
        """Create a histogram."""
        try:
            # Create figure
            fig = px.histogram(
                x=data,
                nbins=bins,
                title=title,
                labels={'x': x_label, 'y': y_label},
                color_discrete_sequence=colors or self.color_palettes.get(theme, self.color_palettes["default"])
            )
            
            # Update layout
            fig.update_layout(
                showlegend=False,
                font=dict(size=12),
                margin=dict(t=50, b=50, l=50, r=50)
            )
            
            # Convert to JSON and image
            chart_json = fig.to_json()
            chart_image = self._fig_to_base64(fig)
            
            return {
                "type": "histogram",
                "title": title,
                "data": chart_json,
                "image": chart_image,
                "config": self.default_config
            }
            
        except Exception as e:
            logger.error(f"Error creating histogram: {e}")
            raise
    
    @traced("chart_generator_create_box_plot")
    async def create_box_plot(
        self,
        data: Dict[str, List[float]],
        title: str,
        y_label: str = "Value",
        colors: Optional[List[str]] = None,
        theme: str = "default"
    ) -> Dict[str, Any]:
        """Create a box plot."""
        try:
            # Create figure
            fig = go.Figure()
            
            for i, (category, values) in enumerate(data.items()):
                fig.add_trace(go.Box(
                    y=values,
                    name=category,
                    marker_color=colors[i] if colors and i < len(colors) else self.color_palettes.get(theme, self.color_palettes["default"])[i % len(self.color_palettes.get(theme, self.color_palettes["default"]))]
                ))
            
            # Update layout
            fig.update_layout(
                title=title,
                yaxis_title=y_label,
                showlegend=False,
                font=dict(size=12),
                margin=dict(t=50, b=50, l=50, r=50)
            )
            
            # Convert to JSON and image
            chart_json = fig.to_json()
            chart_image = self._fig_to_base64(fig)
            
            return {
                "type": "box",
                "title": title,
                "data": chart_json,
                "image": chart_image,
                "config": self.default_config
            }
            
        except Exception as e:
            logger.error(f"Error creating box plot: {e}")
            raise
    
    @traced("chart_generator_create_multi_chart")
    async def create_multi_chart(
        self,
        charts: List[Dict[str, Any]],
        title: str,
        rows: int = 2,
        cols: int = 2,
        theme: str = "default"
    ) -> Dict[str, Any]:
        """Create a multi-chart dashboard."""
        try:
            # Create subplots
            fig = make_subplots(
                rows=rows,
                cols=cols,
                subplot_titles=[chart.get("title", "") for chart in charts[:rows*cols]],
                specs=[[{"secondary_y": False} for _ in range(cols)] for _ in range(rows)]
            )
            
            # Add charts to subplots
            for i, chart in enumerate(charts[:rows*cols]):
                row = (i // cols) + 1
                col = (i % cols) + 1
                
                # Add chart based on type
                if chart["type"] == "bar":
                    fig.add_trace(
                        go.Bar(x=chart["x"], y=chart["y"], name=chart.get("name", "")),
                        row=row, col=col
                    )
                elif chart["type"] == "line":
                    fig.add_trace(
                        go.Scatter(x=chart["x"], y=chart["y"], mode='lines+markers', name=chart.get("name", "")),
                        row=row, col=col
                    )
                elif chart["type"] == "pie":
                    fig.add_trace(
                        go.Pie(labels=chart["labels"], values=chart["values"], name=chart.get("name", "")),
                        row=row, col=col
                    )
            
            # Update layout
            fig.update_layout(
                title=title,
                showlegend=False,
                font=dict(size=10),
                margin=dict(t=80, b=50, l=50, r=50)
            )
            
            # Convert to JSON and image
            chart_json = fig.to_json()
            chart_image = self._fig_to_base64(fig)
            
            return {
                "type": "multi",
                "title": title,
                "data": chart_json,
                "image": chart_image,
                "config": self.default_config
            }
            
        except Exception as e:
            logger.error(f"Error creating multi-chart: {e}")
            raise
    
    def _fig_to_base64(self, fig: go.Figure) -> str:
        """Convert Plotly figure to base64 image."""
        try:
            img_buffer = io.BytesIO()
            fig.write_image(img_buffer, format='png', width=800, height=600)
            img_buffer.seek(0)
            img_base64 = base64.b64encode(img_buffer.read()).decode('utf-8')
            return f"data:image/png;base64,{img_base64}"
        except Exception as e:
            logger.warning(f"Error converting figure to base64: {e}")
            return ""
    
    async def create_security_overview_chart(
        self,
        data: Dict[str, Any],
        theme: str = "security"
    ) -> Dict[str, Any]:
        """Create a comprehensive security overview chart."""
        try:
            # Create multi-chart with security metrics
            charts = [
                {
                    "type": "pie",
                    "title": "Incident Severity",
                    "labels": list(data.get("severity_distribution", {}).keys()),
                    "values": list(data.get("severity_distribution", {}).values())
                },
                {
                    "type": "bar",
                    "title": "Top Threats",
                    "x": list(data.get("top_threats", {}).keys()),
                    "y": list(data.get("top_threats", {}).values())
                },
                {
                    "type": "line",
                    "title": "Incident Trend",
                    "x": [item["date"] for item in data.get("incident_trend", [])],
                    "y": [item["count"] for item in data.get("incident_trend", [])]
                },
                {
                    "type": "gauge",
                    "title": "Security Score",
                    "value": data.get("security_score", 0)
                }
            ]
            
            return await self.create_multi_chart(
                charts,
                "Security Overview Dashboard",
                rows=2,
                cols=2,
                theme=theme
            )
            
        except Exception as e:
            logger.error(f"Error creating security overview chart: {e}")
            raise
    
    async def create_risk_assessment_chart(
        self,
        data: Dict[str, Any],
        theme: str = "risk"
    ) -> Dict[str, Any]:
        """Create a risk assessment visualization."""
        try:
            # Create risk matrix heatmap
            risk_matrix_data = data.get("risk_matrix", [[0]])
            
            return await self.create_heatmap(
                risk_matrix_data,
                "Risk Assessment Matrix",
                ["Low", "Medium", "High"],
                ["Low", "Medium", "High"],
                colorscale="RdYlGn_r",
                theme=theme
            )
            
        except Exception as e:
            logger.error(f"Error creating risk assessment chart: {e}")
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Get chart generator statistics."""
        return {
            "supported_chart_types": [
                "pie", "bar", "line", "scatter", "heatmap", 
                "gauge", "histogram", "box", "multi"
            ],
            "available_themes": list(self.color_palettes.keys()),
            "default_config": self.default_config
        }