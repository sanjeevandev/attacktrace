import json
import os
import re
from typing import List, Dict, Any
from src.models import AttackIncident


class GraphVisualizer:
    def __init__(self) -> None:
        pass

    def export_graph_json(self, incident: AttackIncident) -> Dict[str, Any]:
        """
        Serializes an incident's chronological path into a node-link graph topology.
        Nodes: Attacker IP, Target Users, Resources, MITRE Techniques.
        Edges: Transitions and relation links.
        """
        nodes: Dict[str, Dict[str, Any]] = {}
        edges_list: List[Dict[str, Any]] = []
        seen_edges = set()

        attacker_id = f"attacker:{incident.primary_actor_ip}"
        
        # 1. Attacker Node
        nodes[attacker_id] = {
            "id": attacker_id,
            "label": incident.primary_actor_ip,
            "type": "attacker",
            "risk": max((step.risk_score for step in incident.steps), default=0),
        }

        prev_target_id = None

        for idx, step in enumerate(incident.steps):
            parts = step.actor.split(" -> ")
            user_name = parts[1] if len(parts) > 1 else "None"

            # Parse resource from step description
            match = re.search(r"Accessed\s+(\S+)", step.description)
            resource = match.group(1) if match else "N/A"
            if resource == "N/A":
                resource = "system"

            curr_step_target = attacker_id

            # 2. User Node
            if user_name and user_name != "None":
                user_id = f"user:{user_name}"
                if user_id not in nodes:
                    nodes[user_id] = {
                        "id": user_id,
                        "label": user_name,
                        "type": "user",
                        "risk": step.risk_score,
                    }
                else:
                    nodes[user_id]["risk"] = max(nodes[user_id]["risk"], step.risk_score)

                # Link: Attacker -> User
                edge_key = (attacker_id, user_id, "targeted")
                if edge_key not in seen_edges:
                    edges_list.append({
                        "source": attacker_id,
                        "target": user_id,
                        "action": "targeted",
                        "timestamp": step.timestamp,
                    })
                    seen_edges.add(edge_key)
                
                curr_step_target = user_id

            # 3. Resource Node
            if resource and resource not in ["N/A", "system"]:
                res_id = f"resource:{resource}"
                if res_id not in nodes:
                    nodes[res_id] = {
                        "id": res_id,
                        "label": resource,
                        "type": "resource",
                        "risk": step.risk_score,
                    }
                else:
                    nodes[res_id]["risk"] = max(nodes[res_id]["risk"], step.risk_score)

                # Link: User/Attacker -> Resource
                source_id = user_id if (user_name and user_name != "None") else attacker_id
                edge_key = (source_id, res_id, "accessed")
                if edge_key not in seen_edges:
                    edges_list.append({
                        "source": source_id,
                        "target": res_id,
                        "action": "accessed",
                        "timestamp": step.timestamp,
                    })
                    seen_edges.add(edge_key)

                curr_step_target = res_id

            # 4. MITRE Technique Node
            if step.technique and step.technique != "N/A - Legitimate Action":
                tech_parts = step.technique.split(" - ")
                tech_id = tech_parts[0].strip()
                tech_name = tech_parts[1].strip() if len(tech_parts) > 1 else tech_id

                tech_node_id = f"technique:{tech_id}"
                if tech_node_id not in nodes:
                    nodes[tech_node_id] = {
                        "id": tech_node_id,
                        "label": f"{tech_id}: {tech_name}",
                        "type": "technique",
                        "risk": step.risk_score,
                    }
                else:
                    nodes[tech_node_id]["risk"] = max(nodes[tech_node_id]["risk"], step.risk_score)

                # Link: Resource/User -> Technique
                source_id = curr_step_target
                edge_key = (source_id, tech_node_id, "utilized")
                if edge_key not in seen_edges:
                    edges_list.append({
                        "source": source_id,
                        "target": tech_node_id,
                        "action": "utilized",
                        "timestamp": step.timestamp,
                    })
                    seen_edges.add(edge_key)

            # Link: Chronological step progression
            if prev_target_id and prev_target_id != curr_step_target:
                edge_key = (prev_target_id, curr_step_target, "progressed_to")
                if edge_key not in seen_edges:
                    edges_list.append({
                        "source": prev_target_id,
                        "target": curr_step_target,
                        "action": "progressed_to",
                        "timestamp": step.timestamp,
                    })
                    seen_edges.add(edge_key)

            prev_target_id = curr_step_target

        return {
            "nodes": list(nodes.values()),
            "edges": edges_list,
        }

    def generate_html_report(self, incidents: List[AttackIncident], output_path: str = "report.html") -> str:
        """
        Generates a standalone interactive HTML file displaying incidents.
        Embeds serialized incidents directly into the script template.
        """
        candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "dashboard.html"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", "dashboard.html"),
            os.path.join(os.getcwd(), "templates", "dashboard.html"),
        ]
        template_path = None
        for c in candidates:
            if os.path.exists(c):
                template_path = c
                break

        if not template_path:
            raise FileNotFoundError(f"Dashboard template not found in candidates: {candidates}")

        with open(template_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        # Serialize incidents
        incidents_json = json.dumps([inc.to_dict() for inc in incidents], indent=2)

        # Replace JS array placeholder
        html_content = html_content.replace(
            "window.ATTACKTRACE_INCIDENTS = [];",
            f"window.ATTACKTRACE_INCIDENTS = {incidents_json};"
        )

        # Write output file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return html_content
