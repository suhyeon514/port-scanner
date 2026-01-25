import os
import glob
import json
import sqlite3

# 설정
JSON_DIR = "./data" # NVD JSON 파일들이 있는 디렉토리
DB_PATH = "nvd_vuln.db"

def parse_cpe_criteria(criteria):
    """
    cpe:2.3:a:adobe:coldfusion:9.0.1:... 문자열에서 정보를 추출합니다.
    """
    parts = criteria.split(':')
    if len(parts) >= 6:
        # vendor, product, version 반환
        return parts[3], parts[4], parts[5]
    return None, None, None

def init_db(conn):
    cur = conn.cursor()
    # 기존 테이블이 꼬이지 않도록 삭제 후 재생성
    cur.execute("DROP TABLE IF EXISTS cve_cpe")
    cur.execute("DROP TABLE IF EXISTS cve")
    
    # 1. CVE 테이블
    cur.execute("""
        CREATE TABLE cve (
            id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL
        )
    """)
    
    # 2. CPE 매핑 테이블 (criteria 컬럼 추가됨)
    cur.execute("""
        CREATE TABLE cve_cpe (
            cve_id TEXT,
            vendor TEXT,
            product TEXT,
            version TEXT,
            criteria TEXT,
            vulnerable INTEGER,
            FOREIGN KEY(cve_id) REFERENCES cve(id)
        )
    """)
    
    # 검색 속도 최적화를 위한 인덱스
    cur.execute("CREATE INDEX idx_product ON cve_cpe (product)")
    cur.execute("CREATE INDEX idx_criteria ON cve_cpe (criteria)")
    conn.commit()

def insert_data(conn, cve_obj):
    cur = conn.cursor()
    cve_id = cve_obj.get("id")
    
    # CVSS 점수 추출 로직
    metrics = cve_obj.get("metrics", {})
    cvss_score = 0.0
    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV2" in metrics:
        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    
    # 설명 추출
    description = ""
    for desc in cve_obj.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value")
            break

    cur.execute("INSERT OR REPLACE INTO cve VALUES (?, ?, ?)", (cve_id, description, cvss_score))

    # CPE 데이터 처리
    for config in cve_obj.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria")
                vulnerable = 1 if cpe_match.get("vulnerable") else 0
                vendor, product, version = parse_cpe_criteria(criteria)
                
                if product:
                    # criteria 값을 포함하여 INSERT
                    cur.execute("""
                        INSERT INTO cve_cpe (cve_id, vendor, product, version, criteria, vulnerable)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (cve_id, vendor, product, version, criteria, vulnerable))

def test_search(product_name):
    """DB 구축 후 검색이 잘 되는지 테스트"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    print(f"\n[*] Testing search for: {product_name}")
    cur.execute("""
        SELECT DISTINCT c.id, c.cvss_score, cp.product, cp.criteria
        FROM cve c JOIN cve_cpe cp ON c.id = cp.cve_id 
        WHERE cp.product LIKE ? LIMIT 3
    """, (f"%{product_name}%",))
    rows = cur.fetchall()
    for r in rows:
        print(f" >> Found: {r['id']} | Score: {r['cvss_score']} | Criteria: {r['criteria']}")
    conn.close()

def main():
    if not os.path.exists(JSON_DIR):
        print(f"[!] Error: {JSON_DIR} folder not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    
    json_files = glob.glob(os.path.join(JSON_DIR, "*.json"))
    for file_path in json_files:
        print(f"[*] Processing {file_path}...")
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for item in data.get("vulnerabilities", []):
                insert_data(conn, item.get("cve"))
    
    conn.commit()
    print("\n[+] DB Rebuild Complete with 'criteria' column!")
    
    # 검증 작업
    test_search("coldfusion")
    conn.close()

if __name__ == "__main__":
    main()