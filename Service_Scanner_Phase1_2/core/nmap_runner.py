from datetime import datetime
from zoneinfo import ZoneInfo
import subprocess
from pathlib import Path
import json
import yaml
from collections import defaultdict

from config.port_groups_loader import build_port_list
from core.nmap_parser import parse_nmap_xml_file
from core.nmap_report import build_final_report

#리눅스 시간대 기준 ISO 포맷
# ISO_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
#윈도우 시간대 기준 ISO 포맷
ISO_FORMAT = "%Y-%m-%dT%H-%M-%S%z"

CONFIG_DIR = Path("config")
RUN_DIR = Path("runs")

TCP_STATES = {"open", "filtered", "open|filtered"}
UDP_STATES = {"open", "filtered", "open|filtered", "unfiltered"}


def now_iso() -> str:
    kst = ZoneInfo("Asia/Seoul")
    return datetime.now(kst).strftime(ISO_FORMAT)


def load_yaml(name: str):
    path = CONFIG_DIR / name
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def timing_to_T(timing_profile: str) -> str:
    mapping = {
        "fast": 4,
        "balanced": 3,
        "careful": 2,
    }
    return str(mapping.get(timing_profile, 3))


def collect_udp_uncertain_ports(scan_data: dict) -> dict[str, list[int]]:
    targets = defaultdict(list)
    for host in scan_data.get("hosts", []):
        ip = host.get("address")
        if not ip:
            continue
        for p in host.get("ports", []):
            if p.get("proto") != "udp":
                continue
            if p.get("state") not in UDP_STATES:
                continue
            port = p.get("port")
            if port is None:
                continue
            targets[ip].append(port)
    return targets


def collect_tcp_open_ports(scan_data: dict) -> dict[str, list[int]]:
    targets = defaultdict(list)
    for host in scan_data.get("hosts", []):
        ip = host.get("address")
        if not ip:
            continue
        for p in host.get("ports", []):
            if p.get("proto") != "tcp":
                continue
            if p.get("state") not in TCP_STATES:
                continue
            port = p.get("port")
            if port is None:
                continue
            targets[ip].append(port)
    return targets


def run_primary_scan(profile_name: str, targets: str):
    profiles_cfg = load_yaml("profiles.yaml")
    port_groups_cfg = load_yaml("port_groups.yaml")

    profile = profiles_cfg["profiles"].get(profile_name)
    if not profile:
        raise ValueError(f"Profile {profile_name} not found")

    tcp_ports = build_port_list("tcp", profile_name, profiles_cfg, port_groups_cfg)
    udp_ports = build_port_list("udp", profile_name, profiles_cfg, port_groups_cfg)

    ports = "T:" + ",".join(str(p) for p in tcp_ports) + ",U:" + ",".join(str(p) for p in udp_ports)

    print(
        f"Running nmap with profile {profile_name} on targets {targets} "
        f"with ports {tcp_ports[:3]}... & {udp_ports[:3]}..."
    )

    nmap_policy = profile["nmap_policy"]
    timing_profile = nmap_policy["timing_profile"]
    max_retries = str(nmap_policy["max_retries"])
    # host_timeout_sec = f'{nmap_policy["host_timeout_sec"]}s'

    RUN_DIR.mkdir(exist_ok=True)

    # 하나의 timestamp로 XML/JSON 파일 이름 맞춰줌
    timestamp = now_iso()
    xml_path = RUN_DIR / f"{timestamp}_{profile_name}_phase1_{targets}.xml"
    json_path = RUN_DIR / f"{timestamp}_{profile_name}_phase1_{targets}.json"

    cmd = [
        "nmap",
        "-sSU",
        "-p",
        ports,
        f"-T{timing_to_T(timing_profile)}",
        "--max-retries",
        max_retries,
        # "--host-timeout", host_timeout_sec,
        "-oX",
        str(xml_path),
    ] + targets.split(",")

    print("[*] Running:", " ".join(cmd))
    subprocess.run(cmd, check=False)

    # Convert XML to JSON
    print(f"[*] Parsing XML: {xml_path}")
    scan_data = parse_nmap_xml_file(xml_path)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, ensure_ascii=False, indent=2)

    print(f"[*] JSON output saved to: {json_path}")

    return {
        "scan_data": scan_data,
        "xml_path": xml_path,
        "json_path": json_path,
        "profile_name": profile_name,
        "targets": targets,
        "timestamp": timestamp,
    }

def run_second_pass_services(profile_name: str, scan_data: dict, base_timestamp: str):
    """
    1차 결과 기준으로:
      - TCP open 포트 → 서비스/버전 확인
      - UDP 애매 포트 → 재스캔 + 서비스 확인
    """

    tcp_targets = collect_tcp_open_ports(scan_data)
    udp_targets = collect_udp_uncertain_ports(scan_data)

    # 호스트 단위로 TCP/UDP 포트 합치기
    hosts = set(tcp_targets.keys()) | set(udp_targets.keys())
    if not hosts:
        print("[*] No ports for second-pass. Skipping.")
        return []

    profiles_cfg = load_yaml("profiles.yaml")
    profile = profiles_cfg["profiles"].get(profile_name)
    if not profile:
        raise ValueError(f"Profile {profile_name} not found")

    nmap_policy = profile["nmap_policy"]
    timing_profile = nmap_policy["timing_profile"]
    max_retries = str(nmap_policy["max_retries"])

    results = []

    for ip in hosts:
        t_ports = sorted(set(tcp_targets.get(ip, [])))
        u_ports = sorted(set(udp_targets.get(ip, [])))

        if not t_ports and not u_ports:
            continue

        # nmap -p 포맷 만들기: T:... , U:...
        port_spec_parts = []
        if t_ports:
            port_spec_parts.append("T:" + ",".join(str(p) for p in t_ports))
        if u_ports:
            port_spec_parts.append("U:" + ",".join(str(p) for p in u_ports))
        port_spec = ",".join(port_spec_parts)

        print(f"[*] Phase2 for {ip}: TCP={t_ports} UDP={u_ports}")

        xml_path = RUN_DIR / f"{base_timestamp}_{profile_name}_phase2_{ip}.xml"
        json_path = RUN_DIR / f"{base_timestamp}_{profile_name}_phase2_{ip}.json"

        cmd = [
            "nmap",
            "-sS",
            "-sU",
            "-sV",
            "--version-intensity",
            "9",
            "--max-retries",
            max_retries,
            f"-T{timing_to_T(timing_profile)}",
            "-p",
            port_spec,
            "-oX",
            str(xml_path),
            ip,
        ]

        print("[*] Running (phase2):", " ".join(cmd))
        subprocess.run(cmd, check=False)

        print(f"[*] Parsing XML (phase2): {xml_path}")
        scan2 = parse_nmap_xml_file(xml_path)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(scan2, f, ensure_ascii=False, indent=2)

        print(f"[*] Phase2 JSON saved to: {json_path}")

        results.append(
            {
                "ip": ip,
                "tcp_ports": t_ports,
                "udp_ports": u_ports,
                "xml_path": xml_path,
                "json_path": json_path,
                "scan_data": scan2,
            }
        )

    return results

def run_profile(profile_name: str, targets: str, second_pass: bool = True):
    """
    프로파일 기준으로 1차 스캔을 돌리고,
    second_pass=True면 2차(TCP/UDP 서비스 스캔)까지 수행.
    마지막에 최종 리포트 JSON까지 생성/저장.
    """
    phase1 = run_primary_scan(profile_name, targets)

    if not second_pass:
        # 1차만 돌리고 끝낼 때는 최종 리포트를 간단히 만들 수도 있고,
        # 아니면 phase1만 리턴해도 됨. 여기선 일단 phase1 그대로 리턴.
        return phase1

    # 2차 (TCP open + UDP 애매 포트) 서비스 스캔
    phase2_results = run_second_pass_services(
        profile_name=profile_name,
        scan_data=phase1["scan_data"],
        base_timestamp=phase1["timestamp"],
    )

    # 최종 리포트 구성
    final_report = build_final_report(
        profile_name=profile_name,
        targets=targets,
        phase1=phase1,
        phase2_results=phase2_results,
    )

    # 최종 리포트 저장 (runs/타임스탬프_profile_final.json)
    final_path = RUN_DIR / f"{phase1['timestamp']}_{profile_name}_final_report.json"
    with open(final_path, "w", encoding="utf-8") as f:
        json.dump(final_report, f, ensure_ascii=False, indent=2)

    print(f"[*] Final report saved to: {final_path}")

    # 필요하면 경로까지 같이 리턴
    return {
        "final_path": final_path,
        "final_report": final_report,
    }
