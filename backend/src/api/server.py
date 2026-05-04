import json
import logging
import asyncio
from typing import Dict, Any, List
from aiohttp import web  # type: ignore
from pathlib import Path
import os
import sys
import datetime
from neo4j.time import DateTime, Date, Time  # type: ignore

# Add src to path if needed
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.core.config import config  # type: ignore
from src.utils.logger import get_logger  # type: ignore

logger = get_logger("Cloudscape.API")

class CloudscapeApiServer:
    def __init__(self):
        self.app = web.Application()
        self.setup_routes()
        self._runner = None
        self._site = None
        self._driver = None
        
    def setup_routes(self):
        # Enable permissive CORS for frontend Vite dev server (localhost:5176)
        self.app.add_routes([
            web.options('/api/{tail:.*}', self.handle_cors_preflight),
            web.get('/api/graph', self.get_graph),
            web.get('/api/assets', self.get_assets),
            web.get('/api/blast-radius/{node_id}', self.get_blast_radius),
            web.get('/api/timeline', self.get_timeline),
            web.get('/api/timeline/{snapshot_id}', self.get_timeline_snapshot),
            web.get('/api/events', self.get_events),
            web.get('/api/forensics/trends', self.get_trends),
            web.get('/api/forensics/drift/{arn:.+}', self.get_node_drift),
            web.get('/api/forensics/compare', self.get_comparison)
        ])
        
        # Add CORS headers to all responses
        self.app.middlewares.append(self.cors_middleware)

    @web.middleware
    async def cors_middleware(self, request, handler):
        response = await handler(request)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response

    async def handle_cors_preflight(self, request):
        return web.Response(headers={
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        })

    async def _get_neo4j_session(self):
        if not self._driver:
            from neo4j import AsyncGraphDatabase  # type: ignore
            uri = config.settings.database.neo4j_uri
            user = config.settings.database.neo4j_user
            password = config.settings.database.neo4j_password
            self._driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
        return self._driver.session()  # type: ignore

    async def get_graph(self, request):
        """Returns the full cloud topology graph matching the React frontend format."""
        query = """
        MATCH (n:Resource)
        OPTIONAL MATCH (n)-[r]->(m:Resource)
        RETURN collect(DISTINCT n) as nodes, collect(DISTINCT {source: n.arn, target: m.arn, type: type(r)}) as edges
        """
        try:
            session = await self._get_neo4j_session()
            async with session as s:  # type: ignore
                result = await s.run(query)
                records = await result.fetch(1)
                
                if not records:
                    return web.json_response({"nodes": [], "edges": []})
                    
                record = records[0]
                
                # Format Nodes
                raw_nodes = record.get("nodes", [])
                formatted_nodes = []
                for n_obj in raw_nodes:
                    # In python neo4j driver, properties are accessed dictionary style
                    props = dict(n_obj.items())
                    
                    # Force clean properties of DateTimes
                    clean_props: Dict[str, Any] = {}
                    for k, v in props.items():
                        if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
                            clean_props[k] = v.isoformat()
                        elif isinstance(v, (DateTime, Date, Time)):
                            if hasattr(v, 'iso_format'):
                                clean_props[k] = v.iso_format()  # type: ignore
                            else:
                                clean_props[k] = str(v)
                        else:
                            clean_props[k] = v

                    # Deserialize vulnerabilities natively
                    vulns = []
                    try:
                        v_str = clean_props.get("vulnerabilities_json")
                        if v_str:
                            vulns = json.loads(v_str)
                    except Exception:
                        pass

                    formatted_nodes.append({
                        "id": clean_props.get("arn", clean_props.get("id", "Unknown")),
                        "name": clean_props.get("name", clean_props.get("arn", "Unknown")),
                        "type": clean_props.get("type", "unknown"),
                        "provider": clean_props.get("cloud_provider", "unknown"),
                        "riskScore": float(clean_props.get("risk_score", 0.0)),
                        "permissions": [], # Mock or unroll if needed
                        "vulnerabilities": vulns,
                        "metadata": clean_props
                    })
                
                # Format Edges - filter null targets
                raw_edges = record.get("edges", [])
                edges = [e for e in raw_edges if e and e.get("target")]
                
                return web.json_response({
                    "nodes": formatted_nodes,
                    "edges": edges
                })
                
        except Exception as e:
            logger.error(f"Failed to fetch graph: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def get_assets(self, request):
        """Returns a flat list of assets."""
        try:
            # Reuses the exact graph aggregation logic to pull nodes for the table
            resp = await self.get_graph(request)
            data = json.loads(resp.text)  # type: ignore
            return web.json_response({"assets": data.get("nodes", [])})
        except Exception as e:
            logger.error(f"Failed to fetch assets: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def get_blast_radius(self, request):
        """Returns downstream impacted assets from a given node."""
        node_id = request.match_info['node_id']
        query = """
        MATCH (src:Resource {arn: $node_id})-[r*1..3]->(impacted:Resource)
        RETURN collect(DISTINCT impacted) as nodes, 
               collect(DISTINCT {source: startNode(last(r)).arn, target: endNode(last(r)).arn, type: type(last(r))}) as edges
        """
        try:
            session = await self._get_neo4j_session()
            async with session as s:  # type: ignore
                result = await s.run(query, node_id=node_id)
                records = await result.fetch(1)
                
                if not records:
                    return web.json_response({"nodes": [], "edges": []})
                    
                record = records[0]
                
                formatted_nodes = []
                for n_obj in record.get("nodes", []):
                    props = dict(n_obj.items())
                    
                    clean_props: Dict[str, Any] = {}
                    for k, v in props.items():
                        if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
                            clean_props[k] = v.isoformat()
                        elif isinstance(v, (DateTime, Date, Time)):
                            if hasattr(v, 'iso_format'):
                                clean_props[k] = v.iso_format()  # type: ignore
                            else:
                                clean_props[k] = str(v)
                        else:
                            clean_props[k] = v

                    formatted_nodes.append({
                        "id": clean_props.get("arn", clean_props.get("id", "Unknown")),
                        "name": clean_props.get("name", clean_props.get("arn", "Unknown")),
                        "type": clean_props.get("type", "unknown"),
                        "provider": clean_props.get("cloud_provider", "unknown"),
                        "riskScore": float(clean_props.get("risk_score", 0.0)),
                    })
                
                edges = [e for e in record.get("edges", []) if e and e.get("target")]
                
                # Calculate aggregate risk
                total_risk = sum(n["riskScore"] for n in formatted_nodes)
                overall_risk = total_risk / len(formatted_nodes) if formatted_nodes else 0
                
                return web.json_response({
                    "nodes": formatted_nodes,
                    "edges": edges,
                    "metrics": {
                        "totalAssetsImpacted": len(formatted_nodes),
                        "overallRisk": round(float(overall_risk), 2),  # type: ignore
                        "criticalPaths": len([n for n in formatted_nodes if n["riskScore"] > 80])
                    }
                })
        except Exception as e:
            logger.error(f"Failed to calculate blast radius: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def get_timeline(self, request):
        """Returns a historical timeline of completed scans across the infrastructure."""
        try:
            from src.core.forensics import forensic_ledger
            import os
            import json
            
            base_path = forensic_ledger.base_path
            if not base_path.exists():
                return web.json_response([])
                
            # Get all scan directories sorted by time
            scan_dirs = sorted([d for d in base_path.iterdir() if d.is_dir()], key=lambda x: x.stat().st_mtime)
            
            history = []
            for d in scan_dirs:
                # We only care about COMPLETED scans for the historical asset timeline
                # Find the STAGE_5 (Intelligence) or STAGE_4 (Convergence) snapshot
                snapshots = list(d.glob("STAGE_5_*.json")) or list(d.glob("STAGE_4_*.json"))
                if snapshots:
                    try:
                        with open(snapshots[0], "r") as f:
                            data = json.load(f)
                            history.append({
                                "timestamp": data["metadata"]["timestamp"],
                                "scan_id": d.name,
                                "stage": "COMPLETED",
                                "node_count": data["metadata"]["node_count"],
                                "risk_summary": data.get("state_snapshot", {}).get("risk_score") or 1.0
                            })
                    except Exception:
                        continue
            
            return web.json_response(history)
        except Exception as e:
            logger.error(f"Timeline reconstruction failed: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def get_timeline_snapshot(self, request):
        """Returns static mock snapshot details."""
        return web.json_response({"snapshot": { "id": request.match_info['snapshot_id'] }})
        
    async def get_events(self, request):
        """Returns the persistent security event stream from the Forensic Registry."""
        try:
            from src.core.forensics import event_registry
            return web.json_response(event_registry.events)
        except Exception as e:
            logger.error(f"Event retrieval failed: {e}")
            return web.json_response([], status=500)

    async def get_node_drift(self, request):
        """Returns the deep property-level drift history for a specific resource ARN."""
        arn = request.match_info['arn']
        try:
            from src.core.forensics import forensic_ledger, StateComparator
            scan_dirs = sorted([d for d in forensic_ledger.base_path.iterdir() if d.is_dir()], key=lambda x: x.stat().st_mtime)
            
            history = []
            prev_state = None
            for d in scan_dirs:
                snapshots = list(d.glob("STAGE_5_*.json")) or list(d.glob("STAGE_4_*.json"))
                if snapshots:
                    with open(snapshots[0], "r") as f:
                        data = json.load(f)
                        nodes = data.get("nodes") or data.get("node_sample")
                        if nodes:
                            current_node = next((n for n in nodes if (n.get("arn") or n.get("id")) == arn), None)
                            if current_node and prev_state:
                                prev_node = next((n for n in prev_state if (n.get("arn") or n.get("id")) == arn), None)
                                if prev_node:
                                    diff = StateComparator._deep_diff(prev_node, current_node)
                                    if diff:
                                        history.append({
                                            "timestamp": data["metadata"]["timestamp"],
                                            "scan_id": d.name,
                                            "changes": diff
                                        })
                            prev_state = nodes
            return web.json_response(history)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
    async def get_trends(self, request):
        """Returns historical asset and risk trends for the last 30 scans."""
        try:
            from src.core.forensics import forensic_ledger
            scan_dirs = [d for d in forensic_ledger.base_path.iterdir() if d.is_dir()]
            # Filter for Global cycles if they exist, otherwise fallback to individual
            global_scans = [d for d in scan_dirs if d.name.startswith("GLOBAL_")]
            target_dirs = global_scans if global_scans else scan_dirs
            
            target_dirs = sorted(target_dirs, key=lambda x: x.stat().st_mtime)
            
            trends = []
            for d in target_dirs[-30:]: # Last 30 cycles
                snapshots = sorted(list(d.glob("GLOBAL_SUMMARY*.json")) + list(d.glob("STAGE_5_*.json")) + list(d.glob("STAGE_4_*.json")), 
                                  key=lambda x: x.stat().st_mtime, reverse=True)
                if snapshots:
                    with open(snapshots[0], "r") as f:
                        data = json.load(f)
                        state = data.get("state_snapshot", {})
                        # Strictly pull the URM merged count
                        assets = state.get("nodes", {}).get("merged", data["metadata"]["node_count"])
                        trends.append({
                            "timestamp": data["metadata"]["timestamp"],
                            "assets": assets,
                            "risk": state.get("risk_score") or 1.0
                        })
            return web.json_response(trends)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def get_comparison(self, request):
        """Generates a full infrastructure delta report between two arbitrary scan IDs."""
        scan_a = request.query.get('a')
        scan_b = request.query.get('b')
        if not scan_a or not scan_b:
            return web.json_response({"error": "Provide scan IDs 'a' and 'b'"}, status=400)
            
        try:
            from src.core.forensics import forensic_ledger, StateComparator
            state_a = forensic_ledger.load_latest_state(scan_a)
            state_b = forensic_ledger.load_latest_state(scan_b)
            
            if not state_a or not state_b:
                return web.json_response({"error": "One or both scans not found or empty"}, status=404)
                
            report = StateComparator.compare(state_a, state_b)
            return web.json_response({
                "scan_a": scan_a,
                "scan_b": scan_b,
                "delta": report
            })
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def start(self, host='127.0.0.1', port=4000):
        self._runner = web.AppRunner(self.app)
        await self._runner.setup()  # type: ignore
        self._site = web.TCPSite(self._runner, host, port)
        await self._site.start()  # type: ignore
        logger.info(f"Cloudscape API Native Overlay Server running on http://{host}:{port}")

    async def stop(self):
        if self._driver:
            await self._driver.close()  # type: ignore
        if self._runner:
            await self._runner.cleanup()  # type: ignore
        logger.info("API Overlay Server stopped.")

async def start_api_server():
    server = CloudscapeApiServer()
    await server.start()
    return server
