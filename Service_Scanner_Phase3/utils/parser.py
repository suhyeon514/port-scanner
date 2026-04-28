# utils/parser.py

import re
from typing import Dict, Any

_HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9A-Fa-f]{2}\s*)+")


def _looks_like_hex_escaped_bytes(text: str) -> bool:
    """
    '\\xFF\\xFD\\x18 ...' 형태의 문자열인지 검사.
    공백은 무시하고, 전체가 이 패턴으로만 구성되어 있으면 True.
    """
    if not text:
        return False
    compact = text.strip().replace(" ", "")
    return bool(_HEX_ESCAPE_PATTERN.fullmatch(compact))


def _decode_hex_escapes_to_bytes(text: str) -> bytes:
    """
    '\\xFF\\xFD\\x18' 형태의 문자열을 실제 바이트로 변환.
    """
    compact = text.strip().replace(" ", "")
    # \xHH 패턴만 뽑아서 HH 부분만 모으기
    hex_bytes = re.findall(r"\\x([0-9A-Fa-f]{2})", compact)
    return bytes(int(h, 16) for h in hex_bytes)


def _summarize_telnet_bytes(raw_bytes: bytes) -> str:
    """
    텔넷 IAC(0xFF) 시퀀스를 간단한 요약 문자열로 변환.
    너무 디테일하게 안 가고, “옵션 협상 바이트” 정도만 알려주는 용도.
    """
    if not raw_bytes:
        return "Telnet banner: empty byte sequence"

    # IAC(0xFF)가 얼마나 많은지로 텔넷 협상 여부 추정
    ff_count = sum(1 for b in raw_bytes if b == 0xFF)
    if ff_count == 0:
        return "Binary banner bytes (no printable text)"

    # IAC 시퀀스를 간단히 해석: IAC DO/DONT/WILL/WONT + option
    seq = []
    i = 0
    while i < len(raw_bytes) - 2:
        if raw_bytes[i] == 0xFF:  # IAC
            cmd = raw_bytes[i + 1]
            opt = raw_bytes[i + 2]
            cmd_name = {
                0xFB: "WILL",
                0xFC: "WONT",
                0xFD: "DO",
                0xFE: "DONT",
            }.get(cmd, f"CMD_{cmd:02X}")
            seq.append(f"IAC {cmd_name} 0x{opt:02X}")
            i += 3
        else:
            i += 1

    if not seq:
        return "Telnet negotiation bytes (IAC present), no text banner"

    joined = ", ".join(seq)
    return f"Telnet negotiation only: {joined} (no human-readable banner)"


def clean_script_output(script_data: Dict[str, str], service: str | None = None) -> Dict[str, Any]:
    """
    Nmap script 결과를 정리.
    - banner: 텔넷/바이너리인 경우 사람이 보기 좋은 요약 문자열로 변경
    - 나머지 스크립트: strip() 정도만 수행
    """
    if not script_data:
        return {}

    cleaned: Dict[str, Any] = {}
    service = (service or "").lower()

    for script_id, output in script_data.items():
        if output is None:
            continue

        text = str(output).strip()

        # --- banner 특별 처리 ---
        if script_id == "banner":
            # 1) \xFF\xFD... 형태의 hex-escape인지 확인
            if _looks_like_hex_escaped_bytes(text):
                raw_bytes = _decode_hex_escapes_to_bytes(text)

                # 텔넷이라면 텔넷 전용 요약 사용
                if service == "telnet":
                    cleaned[script_id] = _summarize_telnet_bytes(raw_bytes)
                else:
                    # 일반적인 바이너리 배너 요약
                    cleaned[script_id] = "Binary/non-printable banner bytes (no text banner)"

            else:
                # 사람이 읽을 수 있는 banner면 그대로 사용
                cleaned[script_id] = text

            continue

        # --- 그 외 스크립트는 기본 문자열 처리 ---
        cleaned[script_id] = text

    return cleaned
