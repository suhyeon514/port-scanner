import argparse
import subprocess
import yaml
from pathlib import Path
from parser_nmap_xml import parse_nmap_xml

CONFIG_DIR = Path("../configs")
RUN_DIR = Path("../runs")

def load_yaml(name: str):
    path = CONFIG_DIR / name
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def build_port_list(profile_name: str, profiles_cfg: dict, port_groups_cfg: dict):
    profile = profiles_cfg["profiles"][profile_name]
    tcp_cfg = profile.get("target_defaults", {}).get("tcp")
    
    ports = set()
    
    for group_name in tcp_cfg.get("include_groups", []):
        group_ports = port_groups_cfg["tcp_groups"].get(group_name, []).get("ports", [])
        ports.update(group_ports)
        
    for set_name in tcp_cfg.get("include_sets", []):
        set_def = port_groups_cfg["tcp_sets"].get(set_name, {})
        if set_def.get("mode") == "range":
            ports.update(range(set_def["from"], set_def["to"] + 1))
        elif set_def.get("mode") == "list":
            ports.update(set_def["ports"])
            
    for group_name in tcp_cfg.get("exclude_groups", []):
        group_ports = port_groups_cfg["tcp_groups"][group_name]["ports"]
        ports.difference_update(group_ports)
    
    return sorted(ports)
        
def timing_to_T(timing_profile: str) -> str:
    mapping = {
        "fast": 4,
        "balanced": 3,
        "careful": 2,
    }
    return mapping.get(timing_profile, "3")

def run_nmap(profile_name: str, targets: str):
    profiles_cfg = load_yaml("profiles.yaml")
    port_groups_cfg = load_yaml("port_groups.yaml")
    
    profile = profiles_cfg["profiles"][profile_name]
    if not profile:
        raise ValueError(f"Profile {profile_name} not found")
    
    ports = build_port_list(profile_name, profiles_cfg, port_groups_cfg)
    print(f"Running nmap with profile {profile_name} on targets {targets} with ports {ports[:3]}...")
    
    port_arg = ",".join(str(p) for p in ports)
    
    nmap_policy = profile["nmap_policy"]
    timing_profile = nmap_policy["timing_profile"]
    max_retries = str(nmap_policy["max_retries"])
    # host_timeout_sec = f'{nmap_policy["host_timeout_sec"]}s'
    
    RUN_DIR.mkdir(exist_ok=True)
    xml_path = RUN_DIR / f"{profile_name}.xml"
    json_path = RUN_DIR / f"{profile_name}.json"
    
    cmd = [
        "nmap",
        "-sS",
        "-p", port_arg,
        f"-T{timing_to_T(timing_profile)}",
        "--max-retries", max_retries,
        # "--host-timeout", host_timeout_sec,
        "-oX", str(xml_path),
    ] + targets.split(",")
    
    print("[*] Running:", " ".join(cmd))
    subprocess.run(cmd, check=False)

    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, help="Profile name to run")
    parser.add_argument("--targets", required=True, help="Target to scan")
    args = parser.parse_args()
    
    run_nmap(args.profile, args.targets)
    
if __name__ == "__main__":
    main()