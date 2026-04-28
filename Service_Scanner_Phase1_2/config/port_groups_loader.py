from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml

def build_port_list(protocol: str, profile_name: str, profiles_cfg: dict, port_groups_cfg: dict):
    profile = profiles_cfg["profiles"][profile_name]
    tcp_cfg = profile.get("target_defaults", {}).get(protocol)
    
    ports = set()
    
    for group_name in tcp_cfg.get("include_groups", []):
        group_ports = port_groups_cfg[f"{protocol}_groups"].get(group_name, []).get("ports", [])
        ports.update(group_ports)
        
    for set_name in tcp_cfg.get("include_sets", []):
        set_def = port_groups_cfg[f"{protocol}_sets"].get(set_name, {})
        if set_def.get("mode") == "range":
            ports.update(range(set_def["from"], set_def["to"] + 1))
        elif set_def.get("mode") == "list":
            ports.update(set_def["ports"])
            
    for group_name in tcp_cfg.get("exclude_groups", []):
        group_ports = port_groups_cfg[f"{protocol}_groups"].get(group_name, []).get("ports", [])
        ports.difference_update(group_ports)
    
    return sorted(ports)