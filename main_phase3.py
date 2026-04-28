# main_phase3.py
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import json
import time  # 스캔 시간 측정을 위한 모듈 추가
from core.engine import Phase3Engine
import logging # [추가] 로깅 모듈
from utils.logger import setup_logger # [추가] 로거 설정 함수


OUTPUT_FILE = "results/phase3_report.json"

def load_input_data(filename):
    """1,2 단계 결과 파일(JSON) 로드"""
    if not os.path.exists(filename):
        print(f"[!] Error: Input file '{filename}' not found.")
        logging.error(f"Input file '{filename}' not found.") # [추가]
        return None, []
    
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
        logging.info(f"Loaded input data from {filename}") # [추가]
        
        # [변경] Phase 1/2 결과 리포트(hosts 구조) 지원
        if "hosts" in data:
            # 첫 번째 호스트를 대상으로 설정 (단일 IP 스캔 기준)
            if not data["hosts"]:
                return None, []
            
            host_info = data["hosts"][0]
            target_ip = host_info.get("address")
            
            # state가 'open'인 포트만 추출 및 구조 변환
            open_ports = []
            for p in host_info.get("ports", []):
                if p.get("state") == "open":
                    # proto -> protocol 매핑 및 phase2 정보 포함
                    port_entry = {"port": p.get("port"), "protocol": p.get("proto"), "prior_scan_info": p.get("phase2")}
                    open_ports.append(port_entry)
            
            return target_ip, open_ports
        
        # 기존 open_ports.json 구조 지원
        return data.get('target_ip'), data.get('open_ports', [])

def save_output_data(filename, data):
    """결과를 JSON 파일로 저장"""
    # results 폴더가 없으면 생성
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"\n[+] Analysis Complete! Results saved to: {filename}")
    logging.info(f"Analysis Complete! Results saved to: {filename}") # [추가]

if __name__ == "__main__":
    # 1. 로거 시작 [추가]
    log_file = setup_logger()
    print(f"[*] Logging started. Check details in: {log_file}")
    
    # [변경] 커맨드 라인에서 입력 파일 경로를 받음
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        print("[!] Error: Please provide the path to the Phase 1/2 JSON report as an argument.")
        logging.error("No input file provided via command-line argument.")
        sys.exit(1)

    print("=== Phase 3 Service Enumeration Scanner ===")
    logging.info("=== Phase 3 Scanner Started ===") # [추가]
    
    # 2. 데이터 로드 (전제조건: 1,2단계 완료)
    target_ip, open_ports = load_input_data(input_file)
    
    # 스캔 시작 시간 기록
    start_time = time.time()

    if target_ip and open_ports:
        logging.info(f"Target: {target_ip}, Open Ports: {open_ports}") # [추가]

        # 3. 엔진 구동
        engine = Phase3Engine()
        scan_results = engine.run(target_ip, open_ports)
        
        # [추가] Phase 2 정보(prior_scan_info)를 결과에 병합
        # 포트와 프로토콜을 키로 사용하여 입력 데이터 매핑
        input_port_map = {
            (p.get('port'), p.get('protocol')): p 
            for p in open_ports
        }

        for result in scan_results:
            p_key = (result.get('port'), result.get('protocol'))
            if p_key in input_port_map:
                src_data = input_port_map[p_key]
                # prior_scan_info(phase2)가 존재하고 유효한 경우 결과에 추가
                if src_data.get('prior_scan_info'):
                    result['prior_scan_info'] = src_data['prior_scan_info']

        # 4. 결과 저장 (4단계 전달용)
        final_report = {
            "target_ip": target_ip,
            "total_scanned": len(open_ports),
            "scan_details": scan_results
        }
        save_output_data(OUTPUT_FILE, final_report)

        # 스캔 종료 시간 기록 및 출력
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds.")
        logging.info(f"Scan completed in {elapsed_time:.2f} seconds.")
    else:
        print("[-] No valid targets or ports to scan.")
        logging.warning("No valid targets or ports to scan.") # [추가]
    
    logging.info("=== Phase 3 Scanner Finished ===") # [추가]