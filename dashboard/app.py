import os
import sys
import logging
from pathlib import Path

# ==============================================================================
# ENVIRONMENT BOOTSTRAPPING
# Ensure the Streamlit app can import from the core Project Cloudscape modules
# ==============================================================================
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from neo4j import GraphDatabase, exceptions

from core.config import config

# ==============================================================================
# PAGE CONFIGURATION & INITIALIZATION
# ==============================================================================
st.set_page_config(
    page_title="Cloudscape Nexus 5.0 | Aether",
    page_icon="🌌",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Enterprise Dark Mode UI
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1a1c23; padding: 15px; border-radius: 8px; border-left: 5px solid #00f2fe; }
    h1, h2, h3 { color: #e2e8f0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
    .css-1d391kg { background-color: #1a1c23; }
    </style>
""", unsafe_allow_html=True)

# ==============================================================================
# DATABASE CONNECTION MANAGER
# ==============================================================================
@st.cache_resource
def init_neo4j_driver():
    """Initializes and caches the Neo4j driver connection for the session."""
    uri = config.settings.database.uri
    # Default to local auth for simulation if environment variables aren't injected
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "Cloudscape2026!")
    
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        return driver
    except Exception as e:
        st.error(f"FATAL: Could not connect to Neo4j Enterprise Graph Engine: {e}")
        st.stop()

driver = init_neo4j_driver()

# ==============================================================================
# DATA ACCESS METHODS (CYPHER QUERIES)
# ==============================================================================
@st.cache_data(ttl=60)
def fetch_global_metrics() -> Dict[str, Any]:
    """Fetches high-level node and edge counts."""
    query = """
    MATCH (n:CloudResource)
    OPTIONAL MATCH (n)-[r]->()
    RETURN count(DISTINCT n) as total_nodes, count(DISTINCT r) as total_edges,
           sum(CASE WHEN n._baseline_risk_score > 0.8 THEN 1 ELSE 0 END) as critical_assets
    """
    try:
        with driver.session() as session:
            result = session.run(query).single()
            return {
                "nodes": result["total_nodes"],
                "edges": result["total_edges"],
                "critical": result["critical_assets"]
            }
    except Exception as e:
        st.error(f"Failed to fetch metrics: {e}")
        return {"nodes": 0, "edges": 0, "critical": 0}

@st.cache_data(ttl=60)
def fetch_risk_distribution() -> pd.DataFrame:
    """Aggregates risk scores by cloud provider and resource type."""
    query = """
    MATCH (n:CloudResource)
    WHERE n._resource_type IS NOT NULL
    RETURN n._provider AS Provider, 
           n._resource_type AS ResourceType, 
           count(n) AS Count, 
           avg(n._baseline_risk_score) AS AvgRisk
    ORDER BY AvgRisk DESC
    """
    try:
        with driver.session() as session:
            data = [record.data() for record in session.run(query)]
            return pd.DataFrame(data)
    except Exception as e:
        st.error(f"Failed to fetch risk distribution: {e}")
        return pd.DataFrame()

@st.cache_data(ttl=30)
def fetch_attack_paths() -> pd.DataFrame:
    """Retrieves the synthetic EXFILTRATION_PATH edges calculated by the Aether Engine."""
    query = """
    MATCH (src:CloudResource)-[r:EXFILTRATION_PATH]->(tgt:CloudResource)
    RETURN src.arn AS Entry_Point, 
           tgt.arn AS Critical_Target, 
           r.total_hops AS Hops, 
           r.mathematical_cost AS Cost, 
           r.path_sequence AS Sequence
    ORDER BY r.mathematical_cost ASC
    """
    try:
        with driver.session() as session:
            data = [record.data() for record in session.run(query)]
            return pd.DataFrame(data)
    except Exception as e:
        st.error(f"Failed to fetch attack paths: {e}")
        return pd.DataFrame()

@st.cache_data(ttl=30)
def fetch_cross_cloud_bridges() -> pd.DataFrame:
    """Retrieves all Cross-Cloud Identity federations (Azure -> AWS)."""
    query = """
    MATCH (az:CloudResource)-[r:ASSUMES_ROLE_CROSS_CLOUD]->(aws:CloudResource)
    RETURN az.arn AS Azure_Identity, 
           r.matched_claim AS Claim, 
           aws.arn AS AWS_Target_Role
    """
    try:
        with driver.session() as session:
            data = [record.data() for record in session.run(query)]
            return pd.DataFrame(data)
    except Exception as e:
        st.error(f"Failed to fetch cross-cloud bridges: {e}")
        return pd.DataFrame()

# ==============================================================================
# UI COMPONENTS & LAYOUT
# ==============================================================================
st.sidebar.image("https://upload.wikimedia.org/wikipedia/commons/thumb/1/17/Graph_database_diagram.svg/1024px-Graph_database_diagram.svg.png", use_container_width=True)
st.sidebar.title("Nexus 5.0 Aether")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigation", ["Global Risk Posture", "Attack Path Intelligence", "Cross-Cloud Identity Fabric", "Raw Asset Explorer"])
st.sidebar.markdown("---")
st.sidebar.caption(f"Engine Version: v{config.settings.app_metadata.version}")
st.sidebar.caption("Status: Connected to Neo4j Enterprise")

if page == "Global Risk Posture":
    st.title("🌐 Global Multi-Cloud Risk Posture")
    st.markdown("Macro-level view of aggregated Blast Radius mathematical scoring across all tenants.")

    # Top-Level Metrics
    metrics = fetch_global_metrics()
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Tracked Assets (Nodes)", f"{metrics['nodes']:,}")
    c2.metric("Discovered Relationships (Edges)", f"{metrics['edges']:,}")
    c3.metric("Critical Risk Assets (>0.80)", f"{metrics['critical']:,}", delta="High Priority", delta_color="inverse")

    st.markdown("---")

    # Risk Distribution Charts
    df_risk = fetch_risk_distribution()
    if not df_risk.empty:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Asset Volume by Provider")
            fig_pie = px.pie(df_risk, values='Count', names='Provider', hole=0.4, 
                             color_discrete_sequence=px.colors.sequential.Teal)
            fig_pie.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig_pie, use_container_width=True)

        with col2:
            st.subheader("Average Risk Score by Resource Type")
            # Sort to show the riskiest resources at the top
            df_risk_sorted = df_risk.sort_values(by="AvgRisk", ascending=True).tail(15)
            fig_bar = px.bar(df_risk_sorted, x='AvgRisk', y='ResourceType', color='Provider', 
                             orientation='h', color_discrete_map={"AWS": "#FF9900", "Azure": "#0089D6"})
            fig_bar.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No risk distribution data available. Ensure the discovery scan has completed.")

elif page == "Attack Path Intelligence":
    st.title("🎯 Heuristic Attack Path Discovery")
    st.markdown("Dijkstra-calculated routes from Public Exposure entry points to High-Sensitivity data assets.")
    
    df_paths = fetch_attack_paths()
    
    if not df_paths.empty:
        st.warning(f"**CRITICAL ALERTI:** Detected {len(df_paths)} viable exfiltration routes spanning the graph.")
        
        # Display the paths in a highly readable dataframe
        st.dataframe(
            df_paths,
            column_config={
                "Cost": st.column_config.NumberColumn("Math Cost", format="%.2f"),
                "Hops": st.column_config.NumberColumn("Total Hops"),
                "Entry_Point": st.column_config.TextColumn("Public Entry Node"),
                "Critical_Target": st.column_config.TextColumn("Compromised Asset"),
                "Sequence": st.column_config.TextColumn("Full Graph Path (Nodes & Edges)")
            },
            use_container_width=True,
            hide_index=True
        )

        st.subheader("Top Attack Path Entry Points")
        entry_counts = df_paths['Entry_Point'].value_counts().reset_index()
        entry_counts.columns = ['Entry_Point', 'Number of Paths Originated']
        
        fig_entry = px.bar(entry_counts.head(10), x='Number of Paths Originated', y='Entry_Point', orientation='h', color_discrete_sequence=['#ff4b4b'])
        fig_entry.update_layout(yaxis={'categoryorder':'total ascending'}, plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig_entry, use_container_width=True)

    else:
        st.success("Zero viable Attack Paths detected. Environment is mathematically secure against lateral exfiltration.")

elif page == "Cross-Cloud Identity Fabric":
    st.title("🌉 Cross-Cloud Identity Federation")
    st.markdown("Highlights critical trust bridges where an Azure Service Principal can assume an AWS IAM Role.")

    df_bridges = fetch_cross_cloud_bridges()

    if not df_bridges.empty:
        st.error(f"**LATERAL MOVEMENT RISK:** Found {len(df_bridges)} Active Cross-Cloud Trust Bridges.")
        
        st.dataframe(
            df_bridges,
            column_config={
                "Azure_Identity": st.column_config.TextColumn("Azure Entra ID (Source)"),
                "Claim": st.column_config.TextColumn("Federated Claim / App ID"),
                "AWS_Target_Role": st.column_config.TextColumn("AWS IAM Role (Target)")
            },
            use_container_width=True,
            hide_index=True
        )

        st.info("These bridges represent paths where a compromised Azure account automatically grants access to the AWS control plane.")
    else:
        st.success("No cross-cloud identity bridges detected.")

elif page == "Raw Asset Explorer":
    st.title("🗄️ Raw Asset Explorer")
    st.markdown("Direct query interface for the Universal Resource Model (URM).")

    # Interactive Filter
    tenant_filter = st.text_input("Filter by Tenant ID (Leave blank for all):", value="")
    
    query = """
    MATCH (n:CloudResource)
    """
    if tenant_filter:
        query += f"WHERE n._tenant_id CONTAINS '{tenant_filter}'\n"
        
    query += "RETURN n.arn AS ARN, n._provider AS Provider, n._resource_type AS Type, n._baseline_risk_score AS RiskScore, n._tenant_id AS Tenant LIMIT 1000"

    try:
        with driver.session() as session:
            data = [record.data() for record in session.run(query)]
            df_assets = pd.DataFrame(data)
            
            if not df_assets.empty:
                st.dataframe(
                    df_assets,
                    column_config={
                        "RiskScore": st.column_config.ProgressColumn(
                            "Blast Radius Risk",
                            help="0.0 is secure, 1.0 is critically vulnerable.",
                            format="%.2f",
                            min_value=0.0,
                            max_value=1.0,
                        ),
                    },
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No assets match the current filter.")
    except Exception as e:
        st.error(f"Query failed: {e}")