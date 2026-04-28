import json
import os
import sys
import glob

# 경로 설정: deep_scan 내부의 core 패키지 인식
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from core.scapy_engine import ScapyInferenceEngine
from core.logic import DecisionLogic

def run_bridge(output_filename):
    # runs 폴더에서 가장 최신 final_report 찾기
    list_of_files = glob.glob('runs/*_final_report.json')
    if not list_of_files:
        print("[!] Error: Nmap 리포트를 찾을 수 없습니다.")
        return
    input_file = max(list_of_files, key=os.path.getmtime)
    output_path = os.path.join("runs", output_filename)

    with open(input_file, "r") as f:
        nmap_data = json.load(f)

    engine = ScapyInferenceEngine()
    logic = DecisionLogic()
    host = nmap_data["hosts"][0]
    target_ip = host["address"]
    
    inference_results = []
    print(f"[*] {target_ip}에 대한 심층 추론 시작...")

    for p in host.get("ports", []):
        state = p["state"]
        port = p["port"]
        proto = p.get("proto", "tcp")

        if state in ["filtered", "closed", "open|filtered"]:
            print(f"[*] 분석 중: {port}/{proto} ({state})")
            raw_responses = engine.run_tests(target_ip, port)
            
            # 추론 로직 호출 (결론과 이유를 받아옴)
            analysis = logic.infer_policy(raw_responses, proto)
            
            inference_results.append({
                "port": port,
                "proto": proto,
                "nmap_state": state,
                "raw_responses": raw_responses,
                "inferred_policy": analysis["conclusion"],
                "reasoning": analysis["reason"]
            })

    # 최종 결과 저장
    final_output = {
        "target_ip": target_ip,
        "inference_details": inference_results
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=4, ensure_ascii=False)
    print(f"[+] 분석 완료! 결과 저장 위치: {output_path}")

if __name__ == "__main__":
    run_bridge("open_ports.json")
