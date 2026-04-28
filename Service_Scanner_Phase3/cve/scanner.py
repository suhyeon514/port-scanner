# cve/scanner.py
import threading
import logging
import os
import json
import sqlite3
import time
import re
import requests
from Service_Scanner_Phase3.Service_Scanner_Phase3.config import VULNERS_API_KEY, NVD_DATA_DIR, NVD_API_KEY
from utils.cve_lookup import find_cves_by_cpe


try:
    import vulners
    VulnersApi = vulners.VulnersApi
except ImportError:
    VulnersApi = None

def clean_product_name(product):
    """
    Cleans the product name by removing unnecessary characters and normalizing the format.
    Example: 'Apache httpd (Linux)' -> 'apache'
    """
    if not product:
        return ""
    clean = product.split('/')[0]
    clean = re.sub(r'\(.*?\)', '', clean).strip()
    return clean

def ensure_full_cpe_format(cpe_str):
    """CPE 문자열 뒤에 와일드카드 보정"""
    if cpe_str.count(':') <= 5:
        return f"{cpe_str}:*:*:*:*:*:*:*"
    return cpe_str

class VulnScanner:
    def __init__(self, api_key=None):
        self.logger = logging.getLogger(__name__)
        self.cache = {}
        self.cache_lock = threading.Lock()
        
        # API 상태 플래그 (서킷 브레이커 역할)
        self.api_enabled = True
        self.api_fail_count = 0
        self.api_fail_threshold = 5  # 연속 실패 허용 횟수

        self.api_key = api_key or VULNERS_API_KEY
        self.db_path = os.path.join(NVD_DATA_DIR, "nvd_vuln.db")
      
        
        # Vulners API 초기화
        if VulnersApi and self.api_key:
            try:
                self.api = VulnersApi(api_key=self.api_key)
                self.logger.info("Vulners API initialized successfully.")
            except Exception as e:
                self.logger.error(f"Failed to initialize Vulners API: {e}")
                self.api_enabled = False
        else:
            self.api_enabled = False
            self.logger.warning("Vulners API is disabled (Key missing or module not installed).")


    
    def get_vulnerabilities(self, product, version, cpe, existing_ids=None):

        target_cpe = ensure_full_cpe_format(cpe)

         # 기존 CVE ID를 필터링하기 위한 집합 초기화
        if existing_ids is None:
            existing_ids = set()

        combined_vulns = []
        seen_ids = set()


        

        # 3. 로컬 DB 결과가 부족하거나 API가 켜져있을 때 API 보완
        if self.api_enabled:
            query = f"{product} {version}".strip()
            if query and query not in self.cache:
                api_results = self._fetch_from_api(query)
                for v in api_results:
                    if v["id"] not in seen_ids:
                        v["source"] = "vulners_api"
                        combined_vulns.append(v)
                        seen_ids.add(v["id"])
            elif query in self.cache:
                # 캐시된 데이터 활용
                for v in self.cache[query]:
                    if v["id"] not in seen_ids:
                        combined_vulns.append(v)

        return combined_vulns

    def _fetch_from_api(self, query):
        """test_vulners.py 기반으로 수정된 API 호출부"""
        try:
            # [수정됨] search() 대신 search_bulletins() 사용
            if hasattr(self.api, 'search') and hasattr(self.api.search, 'search_bulletins'):
                results = self.api.search.search_bulletins(query, limit=10)
            else:
                # 구버전 라이브러리 등을 위한 폴백
                results = self.api.search(query, limit=10)

            cleaned_data = []
            for item in results:
                # CVSS 점수 파싱 (test_vulners.py 로직)
                cvss_val = 0.0
                cvss_meta = item.get('cvss')
                if isinstance(cvss_meta, dict):
                    cvss_val = cvss_meta.get('score', 0.0)
                
                cleaned_data.append({
                    "id": item.get("id"),
                    "title": item.get("title", "No Title"),
                    "cvss": cvss_val,
                    "href": item.get("href", "")
                })

            with self.cache_lock:
                self.cache[query] = cleaned_data
            
            return cleaned_data

        except Exception as e:
            self.logger.error(f"Vulners API Error for '{query}': {e}")
            return []
        

class NvdScanner:
    def __init__(self, api_key=None):
        self.logger = logging.getLogger(__name__)
        # config에서 가져오거나 인자로 받은 키 사용 (공백 제거)
        raw_key = api_key or NVD_API_KEY
        self.api_key = raw_key.strip() if raw_key else None

        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {'User-Agent': 'My-Vuln-Scanner-v1.0'}

        if self.api_key:
            self.headers['apiKey'] = self.api_key

        self.logger.info("NvdScanner initialized.")

    def _fetch_from_nvd(self, params, search_type):
        """
        실제로 NVD API를 호출하고 결과를 리스트로 반환하는 내부 함수
        search_type: 로그용 문자열 ('CPE' or 'Keyword')
        """
        results = []
        
        # API 요청 속도 조절 (키 없으면 딜레이)
        if not self.api_key:
            time.sleep(2) 

        try:
            while True:
                response = requests.get(self.base_url, headers=self.headers, params=params, timeout=30)

                if response.status_code == 200:
                    data = response.json()
                    items = data.get('vulnerabilities', [])
                    results.extend(items)

                    # 페이지네이션
                    total_results = data.get('totalResults', 0)
                    current_index = params['startIndex'] + len(items)

                    if current_index >= total_results:
                        break
                    
                    params['startIndex'] = current_index
                    
                    # 반복 요청 시 딜레이
                    if not self.api_key:
                        time.sleep(6)

                elif response.status_code == 404:
                    # 해당 검색 조건에 결과 없음
                    self.logger.info(f"[{search_type}] 검색 결과 없음 (404)")
                    break
                else:
                    self.logger.error(f"[{search_type}] API Error: {response.status_code} - {response.text}")
                    break
                    
        except Exception as e:
            self.logger.error(f"[{search_type}] Request Exception: {e}")

        return results

    def get_vulnerabilities(self, product, version, cpe=None):
        """
        1. CPE 기반 검색 수행
        2. 텍스트 키워드 기반 검색 수행
        3. 결과 통합 및 중복 제거 후 반환
        """
        self.logger.info(f"Starting Hybrid Scan for: {product} {version}")
        
        # 중복 제거를 위해 Dictionary 사용 (Key: CVE ID)
        unique_vulnerabilities = {}

        # -------------------------------------------------------
        # Phase 1: CPE 기반 검색 (정확도 우선)
        # -------------------------------------------------------
        if cpe and cpe.startswith("cpe:2.3"):
            target_cpe = ensure_full_cpe_format(cpe)
            self.logger.info(f"[*] Phase 1: CPE 검색 시작 ({target_cpe})")
            
            cpe_params = {
                'cpeName': target_cpe,
                'resultsPerPage': 2000,
                'startIndex': 0
            }
            
            cpe_results = self._fetch_from_nvd(cpe_params, "CPE")
            
            for item in cpe_results:
                cve_id = item['cve']['id']
                unique_vulnerabilities[cve_id] = item
            
            self.logger.info(f"    -> CPE 검색으로 {len(cpe_results)}건 확보")

        # -------------------------------------------------------
        # Phase 2: 텍스트 키워드 검색 (보완용)
        # -------------------------------------------------------
        search_query = f"{product} {version}"
        self.logger.info(f"[*] Phase 2: 키워드 검색 시작 ('{search_query}')")
        
        keyword_params = {
            'keywordSearch': search_query,
            'resultsPerPage': 2000,
            'startIndex': 0
        }
        
        keyword_results = self._fetch_from_nvd(keyword_params, "Keyword")
        
        new_count = 0
        for item in keyword_results:
            cve_id = item['cve']['id']
            # 이미 CPE 검색에서 찾은 거라면 건너뜀 (중복 방지)
            if cve_id not in unique_vulnerabilities:
                unique_vulnerabilities[cve_id] = item
                new_count += 1
        
        self.logger.info(f"    -> 키워드 검색으로 {new_count}건 추가 확보 (중복 제외)")

        # -------------------------------------------------------
        # 결과 정리 및 파싱 (기존 로직 유지)
        # -------------------------------------------------------
        final_raw_list = list(unique_vulnerabilities.values())
        
        if not final_raw_list:
            self.logger.info("최종적으로 발견된 취약점이 없습니다.")
            return []

        # 최신 순 정렬
        final_raw_list.sort(key=lambda x: x['cve']['published'], reverse=True)

        # 상위 10개만 추출
        vuln_list = []
        for item in final_raw_list[:10]:
            cve = item.get('cve', {})
            cve_id = cve.get('id')

            descriptions = cve.get('descriptions', [])
            desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), "No description")

            metrics = cve.get('metrics', {})
            score = "N/A"
            severity = "N/A"

            # V3.1 우선 확인
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                score = cvss_data['baseScore']
                severity = cvss_data['baseSeverity']
            # V2 확인
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                score = cvss_data['baseScore']
                severity = metrics['cvssMetricV2'][0]['baseSeverity']

            vuln_list.append({
                "id": cve_id,
                "title": desc,
                "cvss": score,
                "severity": severity,
                "href": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "source": "nvd_api"
            })

        self.logger.info(f"최종 반환: {len(vuln_list)}건 (통합 검색 완료)")
        return vuln_list

class LocalScanner:
    def __init__(self, db_path=None):
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path or os.path.join(NVD_DATA_DIR, "nvd_vuln.db")
        self.logger.info("LocalDB initialized.")

    def search_vulnerabilities_by_cpe(self, cpe):
        """
        Searches the local database for vulnerabilities based on the given CPE.
        :param cpe: The CPE string to search for.
        :return: A list of vulnerabilities matching the CPE.
        """
        target_cpe = ensure_full_cpe_format(cpe)
        self.logger.info(f"Searching LocalDB for vulnerabilities with CPE: {target_cpe}")
        results = []

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()

                cur.execute("""
                    SELECT DISTINCT c.id, c.description, c.cvss_score, cp.criteria
                    FROM cve c
                    JOIN cve_cpe cp ON c.id = cp.cve_id
                    WHERE cp.criteria = ?
                """, (target_cpe,))

                rows = cur.fetchall()
                for row in rows:
                    results.append({
                        "id": row["id"],
                        "description": row["description"],
                        "cvss": row["cvss_score"],
                        "criteria": row["criteria"],
                        "source": "local_db"
                    })

            self.logger.info(f"Found {len(results)} vulnerabilities for CPE: {target_cpe}")
        except sqlite3.Error as e:
            self.logger.error(f"Error accessing LocalDB: {e}")

        return results
    
