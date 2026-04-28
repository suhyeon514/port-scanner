# core/report.py
from typing import Any, Dict, List, Tuple
from collections import defaultdict


def _extract_ports_by_phase(
    scan_data: Dict[str, Any],
    phase_label: str,
    index: Dict[Tuple[str, str, int], Dict[str, Any]],
):
    """
    scan_data: nmap_parser.py에서 만든 구조 (scan_info + hosts[*].ports[*])
    phase_label: "phase1" 또는 "phase2"
    index: (ip, proto, port) -> merged entry dict
    """
    for host in scan_data.get("hosts", []):
        ip = host.get("address")
        hostname = host.get("hostname")
        status = host.get("status")
        if not ip:
            continue

        for p in host.get("ports", []):
            proto = p.get("proto")
            port = p.get("port")
            if proto is None or port is None:
                continue

            key = (ip, proto, int(port))

            if key not in index:
                index[key] = {
                    "host_address": ip,
                    "hostname": hostname,
                    "host_status": status,
                    "proto": proto,
                    "port": int(port),
                    "phase1": None,
                    "phase2": None,
                }

            # 이 phase에서의 포트 상태/서비스 정보만 뽑아서 저장
            phase_info = {
                "state": p.get("state"),
                "reason": p.get("reason"),
                "reason_ttl": p.get("reason_ttl"),
                "service": p.get("service"),
            }

            index[key][phase_label] = phase_info


def build_final_report(
    profile_name: str,
    targets: str,
    phase1: Dict[str, Any],
    phase2_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    phase1: run_primary_scan()에서 반환한 dict
            { "scan_data": ..., "xml_path": ..., "json_path": ..., "timestamp": ... }
    phase2_results: run_second_pass_services()에서 반환한 리스트
            [ { "ip": ..., "scan_data": ... }, ... ]

    반환값: 최종 리포트 JSON(dict)
    """
    phase1_scan = phase1["scan_data"]

    # (ip, proto, port) 기준으로 phase1/phase2 정보 merge
    index: Dict[Tuple[str, str, int], Dict[str, Any]] = {}

    # 1) phase1 데이터 넣기
    _extract_ports_by_phase(phase1_scan, "phase1", index)

    # 2) phase2 데이터 넣기 (여러 host별 scan_data를 순회)
    for item in phase2_results:
        scan2 = item.get("scan_data")
        if not scan2:
            continue
        _extract_ports_by_phase(scan2, "phase2", index)

    # host 단위로 묶기
    hosts_map: Dict[str, Dict[str, Any]] = {}

    for (ip, proto, port), merged in index.items():
        host_entry = hosts_map.get(ip)
        if host_entry is None:
            host_entry = {
                "address": ip,
                "hostname": merged.get("hostname"),
                "status": merged.get("host_status"),
                "ports": [],
            }
            hosts_map[ip] = host_entry

        phase1_info = merged.get("phase1")
        phase2_info = merged.get("phase2")

        # 최종 state: phase2 있으면 phase2.state, 아니면 phase1.state
        final_state = None
        if phase2_info and phase2_info.get("state") is not None:
            final_state = phase2_info.get("state")
        elif phase1_info and phase1_info.get("state") is not None:
            final_state = phase1_info.get("state")

        port_entry = {
            "proto": merged["proto"],
            "port": merged["port"],
            "state": final_state,
            "phase1": phase1_info,
            "phase2": phase2_info,
        }

        host_entry["ports"].append(port_entry)

    # hosts 리스트로 변환
    hosts_list = list(hosts_map.values())

    # meta 정보 구성
    scan_info = phase1_scan.get("scan_info", {})

    report: Dict[str, Any] = {
        "meta": {
            "profile": profile_name,
            "targets": [t for t in targets.split(",") if t],
            "timestamp": phase1["timestamp"],
            "nmap_args_phase1": scan_info.get("args"),
            "nmap_version": scan_info.get("nmap_version"),
            "phase1_xml": str(phase1["xml_path"]),
            "phase1_json": str(phase1["json_path"]),
        },
        "hosts": hosts_list,
    }

    return report