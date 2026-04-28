"""
nmap XML -> JSON 파서

사용 예시:

1) 파일에서 읽기
    python nmap_parser.py scan.xml > scan.json

2) nmap 출력 바로 파싱
    nmap -sSU -p- -T4 -oX - 10.10.10.10 | python nmap_parser.py

3) 다른 코드에서 사용
    from nmap_parser import parse_nmap_xml_file
    data = parse_nmap_xml_file("scan.xml")
"""

import sys
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, TextIO


def _safe_int(value: Optional[str], default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _safe_float(value: Optional[str], default: Optional[float] = None) -> Optional[float]:
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _parse_scan_info(root: ET.Element) -> Dict[str, Any]:
    """루트 <nmaprun> 요소에서 전체 스캔 메타데이터 추출"""
    info: Dict[str, Any] = {
        "args": root.get("args"),
        "start_time": _safe_int(root.get("start")),
        "nmap_version": root.get("version"),
        "xmloutputversion": root.get("xmloutputversion"),
    }

    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            info["end_time"] = _safe_int(finished.get("time"))
            info["elapsed"] = _safe_float(finished.get("elapsed"))

    return info


def _parse_service(service_elem: ET.Element) -> Dict[str, Any]:
    """<service> 요소를 dict로 변환"""
    service: Dict[str, Any] = {
        "name": service_elem.get("name"),
    }

    # Optional 필드들
    for attr in ("product", "version", "extrainfo", "ostype", "method", "conf"):
        val = service_elem.get(attr)
        if val is not None:
            # conf 같은 건 int일 수도 있지만, 그냥 문자열로 두는 게 안전
            service[attr] = val

    return service


def _parse_port(port_elem: ET.Element) -> Dict[str, Any]:
    """<port> 요소 하나를 dict로 변환"""
    port_dict: Dict[str, Any] = {
        "proto": port_elem.get("protocol"),
        "port": _safe_int(port_elem.get("portid"), 0),
    }

    # state 정보
    state_elem = port_elem.find("state")
    if state_elem is not None:
        port_dict["state"] = state_elem.get("state")
        reason = state_elem.get("reason")
        if reason is not None:
            port_dict["reason"] = reason

        reason_ttl = _safe_int(state_elem.get("reason_ttl"))
        if reason_ttl is not None:
            port_dict["reason_ttl"] = reason_ttl

        reason_ip = state_elem.get("reason_ip")
        if reason_ip is not None:
            port_dict["reason_ip"] = reason_ip
    else:
        # state가 없을 일은 거의 없지만, 방어코드
        port_dict["state"] = None

    # service 정보
    service_elem = port_elem.find("service")
    if service_elem is not None:
        port_dict["service"] = _parse_service(service_elem)
    else:
        port_dict["service"] = None

    return port_dict


def _parse_host(host_elem: ET.Element) -> Dict[str, Any]:
    """<host> 요소 하나를 dict로 변환"""
    host_dict: Dict[str, Any] = {}

    # status
    status_elem = host_elem.find("status")
    if status_elem is not None:
        host_dict["status"] = status_elem.get("state")
    else:
        host_dict["status"] = None

    # address (ipv4 우선, 없으면 첫 address)
    address_elem = host_elem.find("address[@addrtype='ipv4']")
    if address_elem is None:
        address_elem = host_elem.find("address")
    if address_elem is not None:
        host_dict["address"] = address_elem.get("addr")
    else:
        host_dict["address"] = None

    # hostname (있으면 하나만)
    hostname_elem = host_elem.find("hostnames/hostname")
    if hostname_elem is not None:
        host_dict["hostname"] = hostname_elem.get("name")
    else:
        host_dict["hostname"] = None

    # ports
    ports_list: List[Dict[str, Any]] = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            ports_list.append(_parse_port(port_elem))

    host_dict["ports"] = ports_list

    return host_dict


def parse_nmap_xml_root(root: ET.Element) -> Dict[str, Any]:
    """
    <nmaprun> root Element를 JSON용 dict로 변환
    (가장 핵심 함수)
    """
    result: Dict[str, Any] = {
        "scan_info": _parse_scan_info(root),
        "hosts": [],
    }

    hosts: List[Dict[str, Any]] = []
    for host_elem in root.findall("host"):
        hosts.append(_parse_host(host_elem))

    result["hosts"] = hosts
    return result


def parse_nmap_xml_file(path: str) -> Dict[str, Any]:
    """
    XML 파일 경로를 받아서 JSON용 dict로 파싱
    """
    tree = ET.parse(path)
    root = tree.getroot()
    return parse_nmap_xml_root(root)


def parse_nmap_xml_stream(stream: TextIO) -> Dict[str, Any]:
    """
    stream(stdin 등)에서 XML 텍스트를 읽어서 JSON용 dict로 파싱
    """
    tree = ET.parse(stream)
    root = tree.getroot()
    return parse_nmap_xml_root(root)


def main(argv: List[str]) -> int:
    """
    CLI 엔트리포인트
    - 인자 없으면 stdin에서 XML 읽음
    - 인자 하나면 해당 파일에서 XML 읽음
    """
    if len(argv) == 0 or (len(argv) == 1 and argv[0] == "-"):
        # stdin
        data = parse_nmap_xml_stream(sys.stdin)
    elif len(argv) == 1:
        data = parse_nmap_xml_file(argv[0])
    else:
        print(f"Usage: {sys.argv[0]} [nmap_xml_file | -]", file=sys.stderr)
        return 1

    json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
