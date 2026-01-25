# cve/scanner.py
import threading
import logging
import os
import json
import sqlite3
import re
from config import VULNERS_API_KEY, NVD_DATA_DIR
from utils.cve_lookup import find_cves_by_cpe

try:
    import vulners
    VulnersApi = vulners.VulnersApi
except ImportError:
    VulnersApi = None

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


    
    def get_vulnerabilities(self, cpe=None, product=None, version=None):
        """
        로컬 DB와 API를 결합하여 취약점 리스트를 반환합니다.
        """
        combined_vulns = []
        seen_ids = set()

        # Nmap의 cpe 형식이 'cpe:/a:vendor:product:version' 일 경우 
        # 로컬 DB의 'cpe:2.3:a:vendor:product:version' 형식과 맞추기 위해 정규화가 필요할 수 있습니다.
        clean_cpe = cpe.replace('cpe:/', 'cpe:2.3:') if cpe else None

        # 1. 제품명 정규화 (예: 'Apache httpd' -> 'apache')
        clean_product = self._clean_product_name(product)
        
        # 2. 로컬 DB 검색 (최우선)
        self.logger.info(f"Searching Local DB for: {clean_product} {version}")

        local_results = find_cves_by_cpe(cpe_string=clean_cpe, product=clean_product, version=version)
        # local_results = find_cves_by_cpe(cpe_string=cpe, product=clean_product, version=version)
        
        self.logger.info(f"Local DB found {len(local_results)} vulnerabilities.")

        for v in local_results:
            v["source"] = "local_db"
            combined_vulns.append(v)
            seen_ids.add(v["id"])

        # 3. 로컬 DB 결과가 부족하거나 API가 켜져있을 때 API 보완
        if self.api_enabled:
            query = f"{clean_product} {version}".strip()
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

    def _clean_product_name(self, product):
        if not product: return ""
        clean = product.split('/')[0]
        clean = re.sub(r'\(.*?\)', '', clean).strip()
        return clean