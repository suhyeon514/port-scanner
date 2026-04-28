# core/engine.py
import nmap
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from Service_Scanner_Phase3.Service_Scanner_Phase3.config import (
    MAX_WORKERS,
    TIMEOUT,
    NMAP_STABLE_ARGS,
    NMAP_SCRIPT_TIMEOUT,
    NMAP_VERSION_SCAN_ARGS,
    VULNERS_API_KEY,
    NVD_API_KEY
)
from core.dispatcher import get_scripts_for_service
from utils.parser import clean_script_output
from utils.cve_lookup import find_cves_by_cpe
from cve.scanner import VulnScanner, NvdScanner, LocalScanner  # [변경] NvdScanner 추가 임포트



class Phase3Engine:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.vuln_scanner = VulnScanner()
        self.nvd_scanner = NvdScanner() # NvdScanner 초기화
        self.local_scanner = LocalScanner() # LocalScanner 초기화
        self.logger.info("VulnScanner initialized in Phase3Engine.")

    def _normalize_port_data(self, open_ports):
        """
        [입력 데이터 정규화]
        입력이 단순 숫자 리스트([80, 443])일 수도 있고,
        딕셔너리 리스트([{'port':80}, {'port':53, 'protocol':'udp'}])일 수도 있습니다.
        이를 모두 표준 포맷인 딕셔너리 리스트로 변환합니다.
        """
        normalized = []
        for item in open_ports:
            # Case 1: 입력이 단순 숫자(int)인 경우 -> TCP로 간주
            if isinstance(item, int):
                normalized.append({"port": item, "protocol": "tcp"})
            
            # Case 2: 입력이 딕셔너리인 경우
            elif isinstance(item, dict):
                # protocol 키가 없으면 tcp를 기본값으로 설정
                if 'protocol' not in item:
                    item['protocol'] = 'tcp'
                normalized.append(item)
                
        return normalized

    def run(self, target_ip, open_ports):
        """
        [Main Loop] 전체 포트에 대해 병렬 스캔 작업을 시작합니다.
        """
        logger = logging.getLogger(__name__)
        results = []
        
        # 1. 입력 데이터 정규화 (숫자만 들어와도 죽지 않게 처리)
        tasks = self._normalize_port_data(open_ports)
        
        print(f"[*] Starting Phase 3 Logic on {target_ip} ({len(tasks)} tasks)...")
        print(f"    (Workers: {MAX_WORKERS}, Timeout: {TIMEOUT}s)")
        
        logger.info(
            f"Starting Scan on {target_ip}. Tasks: {len(tasks)}, "
            f"Workers: {MAX_WORKERS}, Timeout: {TIMEOUT}"
        )

        # 2. 스레드 풀 실행 (TCP 53번과 UDP 53번은 서로 다른 Task로 취급되어 병렬 실행됨)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_task = {
                executor.submit(self._analyze_port, target_ip, task_info): task_info
                for task_info in tasks
            }

            for future in as_completed(future_to_task):
                task_info = future_to_task[future]
                port = task_info['port']
                proto = task_info['protocol']
                
                try:
                    data = future.result()
                    results.append(data)

                    status = data.get("status", "unknown")
                    service = data.get("service", "")
                    
                    # 출력 시 프로토콜 구분 표시 (예: 53/udp)
                    print(f"   [+] {port}/{proto} Finished ({status}): {service}")
                    
                    logger.info(
                        f"[{port}/{proto}] Analysis Finished. "
                        f"Status={status}, Service={service}"
                    )
                except Exception as e:
                    print(f"   [-] Error scanning {port}/{proto}: {e}")
                    logger.error(
                        f"[{port}/{proto}] Critical Error: {e}", exc_info=True
                    )
        
        return results

    def _analyze_port(self, ip, port_info):
        """
        [Worker Thread] 단일 작업(1 Port + 1 Protocol) 분석
        """
        logger = logging.getLogger(__name__)
        nm = nmap.PortScanner()
        start_time = time.time()

        port = port_info['port']
        # 안전하게 소문자로 변환 (입력이 'UDP'여도 'udp'로 처리)
        protocol = port_info.get('protocol', 'tcp').lower()

        # [기본 결과 스키마]
        result = {
            "port": port,
            "protocol": protocol,
            "status": "init",
            "service": "",
            "product": "",
            "version": "",
            "confidence": 0,    # 신뢰도
            "service_fp": "",   # 서비스 시그니처
            "extrainfo": "",    # 추가 정보 (OS 추정 등)
            "cpe": "",
            "scripts_executed": [],
            "scripts_output": {},
            "vulnerabilities": [], 
            "error_message": "",
            "duration": 0.0,
            "scripts_status": "not_run",
            "scripts_output_count": 0,
        }

        # [Nmap 옵션 설정]
        if protocol == 'udp':
            scan_flag = "-sU"
            proto_specific_args = f"{scan_flag}"
        else:
            scan_flag = "-sS" 
            proto_specific_args = f"{scan_flag}"

        version_args = f"{proto_specific_args} {NMAP_VERSION_SCAN_ARGS} {NMAP_STABLE_ARGS}".strip()
        script_args = f"{proto_specific_args} {NMAP_STABLE_ARGS} --script-timeout {NMAP_SCRIPT_TIMEOUT}s".strip()
        
        logger.info(f"[{port}/{protocol}] Starting analysis on {ip}")

        # -----------------------------------------------------------
        # Step 1: 서비스 버전 탐지
        # -----------------------------------------------------------
        try:
            logger.debug(f"[{port}/{protocol}] Step 1: Version detection started.")
            
            nm.scan(ip, str(port), arguments=version_args, timeout=TIMEOUT)

            
            # 결과 데이터 유효성 검사
            if ip not in nm.all_hosts() or protocol not in nm[ip] or port not in nm[ip][protocol]:
                logger.warning(f"[{port}/{protocol}] No response from Nmap.")
                result["status"] = "no-response"
                result["duration"] = time.time() - start_time
                return result
            
            port_data = nm[ip][protocol][port]
            result["service"] = port_data.get("name", "unknown")
            result["product"] = port_data.get("product", "")
            result["version"] = port_data.get("version", "")
            result["cpe"] = port_data.get("cpe", "")
            result["extrainfo"] = port_data.get("extrainfo", "")
            
            # Convert CPE to v2.3 format if available
            raw_cpe = port_data.get("cpe", "")
            if raw_cpe.startswith("cpe:/"):
                result["cpe"] = raw_cpe.replace("cpe:/", "cpe:2.3:")
            else:
                result["cpe"] = raw_cpe
            
            try:
                result["confidence"] = int(port_data.get("conf", 0))
            except (ValueError, TypeError):
                result["confidence"] = 0
                
            result["service_fp"] = port_data.get("servicefp", "")
            logger.info(f"[{port}/{protocol}] Service detected: {result['service']}")

        except (nmap.PortScannerTimeout, Exception) as e:
            # UDP 스캔 시 가장 많이 발생하는 타임아웃 예외 처리
            err_msg = "Scanner Timeout" if "timeout" in str(e).lower() else f"Error: {e}"
            logger.error(f"[{port}/{protocol}] Step 1 Failed: {err_msg}")
            result["status"] = "timeout" if "timeout" in err_msg.lower() else "error"
            result["error_message"] = err_msg
            result["duration"] = time.time() - start_time
            return result # 버전 탐지 실패 시 이후 단계(스크립트 등) 진행 불가하므로 반환
        
        # -----------------------------------------------------------
        # Step 2: 스크립트 선정
        # -----------------------------------------------------------
        scripts_to_run = get_scripts_for_service(result["service"])
        
        if scripts_to_run:
            result["scripts_executed"] = [s.strip() for s in scripts_to_run.split(",")]
        else:
            result["scripts_executed"] = []

        # -----------------------------------------------------------
        # Step 3: 스크립트 실행
        # -----------------------------------------------------------
        script_results = {}
        
        if scripts_to_run:
            try:
                full_command = f'nmap {script_args} --script "{scripts_to_run}" -p {port} {ip}'
                logger.debug(f"[{port}/{protocol}] Executing Script: {full_command}")

                nm.scan(ip, str(port), arguments=f'{script_args} --script "{scripts_to_run}"', timeout=TIMEOUT)
                
                if ip not in nm.all_hosts() or protocol not in nm[ip] or port not in nm[ip][protocol]:
                    # 스크립트 단계 실패 (부분 성공 처리)
                    msg = f"   [!] {port}/{protocol}: Script scan returned no data."
                    print(msg)
                    logger.error(f"[{port}/{protocol}] Script phase failed (timeout/error).")
                    if result["status"] == "init": result["status"] = "partial"
                    result["scripts_status"] = "error"
                    result["error_message"] = "NSE phase failed"
                
                elif "script" in nm[ip][protocol][port]:
                    # [성공] 결과 파싱
                    script_results = clean_script_output(
                        nm[ip][protocol][port]["script"], 
                        service=result["service"]
                    )
                    result["scripts_status"] = "ok"
                    result["scripts_output_count"] = len(script_results)
                    logger.info(f"[{port}/{protocol}] Scripts executed. Count: {len(script_results)}")
                else:
                    # [성공했으나 출력 없음]
                    result["scripts_status"] = "no_output"
                    result["scripts_output_count"] = 0
            
            except Exception as e:
                logger.error(f"[{port}/{protocol}] Step 3 Exception: {e}", exc_info=True)
                if result["status"] == "init": result["status"] = "partial"
                result["scripts_status"] = "error"
                result["error_message"] = f"Step3 error: {e}"

        result["scripts_output"] = script_results

        # -----------------------------------------------------------
        # Step 4: 결과 패키징 및 취약점 통합
        # -----------------------------------------------------------
        logger.info(f"[{port}/{protocol}] Step 4: CVE Lookup started.")
                    
        logger.info(f"[{port}] Starting CVE lookup for {result['product']} {result['version']} CPE: {result['cpe']}")
        try:
            logger.info(f"[{port}] Querying NvdScanner for vulnerabilities.")
            # NVD API 검색 및 결과 통합
            if result["product"]:
                nvd_vulns = self.nvd_scanner.get_vulnerabilities(
                    product=result["product"],
                    version=result["version"],
                    cpe=result["cpe"]
                )

                # 중복 제거 및 병합 (CVE ID 기준)
                existing_ids = {v['id'] for v in result["vulnerabilities"]}
                for nv in nvd_vulns:
                    if nv['id'] not in existing_ids:
                        result["vulnerabilities"].append(nv)
                        existing_ids.add(nv['id'])
                logger.info(f"[{port}] NvdScanner found {len(nvd_vulns)} vulnerabilities.")

            # 로컬 DB 검색 및 결과 통합
            logger.info(f"[{port}] Querying LocalScanner for vulnerabilities.")
            local_vulns = self.local_scanner.search_vulnerabilities_by_cpe(
                cpe=result["cpe"]
            )

            for lv in local_vulns:
                if lv['id'] not in existing_ids:
                    result["vulnerabilities"].append(lv)
                    existing_ids.add(lv['id'])

            #cve 검색 결과 로그, vulnerabilities 키의 ID 값을 기준으로 vulners api 에 요청
            # logger.info(f"[{port}] Existing CVE IDs after NVD and Local DB: {existing_ids}")

            # # local과 nvd api를 사용 했음에도 결과가 없을 때만 Vulners API 사용
            # if not result["vulnerabilities"]:
            #     # Vulners API 및 로컬 DB 검색
            #     logger.info(f"[{port}] Querying VulnScanner for vulnerabilities.")

            #     # 이미 수집된 CVE ID를 필터링
            #     existing_ids = {v['id'] for v in result["vulnerabilities"]}
            #     logger.info(f"[{port}] Existing CVE IDs before VulnScanner: {existing_ids}")
            #     # Vulners API 호출
            #     vulns = self.vuln_scanner.get_vulnerabilities(
            #         product=result["product"],
            #         version=result["version"],
            #         cpe=result["cpe"],
            #         existing_ids=existing_ids
            #     )

            #     # 중복되지 않은 취약점만 추가
            #     for vuln in vulns:
            #         if vuln['id'] not in existing_ids:
            #             result["vulnerabilities"].append(vuln)
            #             existing_ids.add(vuln['id'])

            #     logger.info(f"[{port}] VulnScanner found {len(vulns)} vulnerabilities.")

            

            logger.info(f"[{port}] Found {len(result['vulnerabilities'])} vulnerabilities (Total)")
        except Exception as e:
            logger.error(f"[{port}] CVE lookup error: {e}")
            


        # 상태 최종 업데이트
        if result["status"] in ("init", ""):
            result["status"] = "success"

        # Nuclei 연동용 힌트
        target_url = f"{ip}:{port}"
        if result["service"] in ['http', 'http-alt', 'http-proxy']:
            target_url = f"http://{ip}:{port}"
        elif result["service"] in ['https', 'ssl/http']:
            target_url = f"https://{ip}:{port}"
            
        result["nuclei_hint"] = {
            "target_url": target_url,
            "service": result["service"],
            "protocol": protocol
        }

        result["duration"] = time.time() - start_time
        
        return result