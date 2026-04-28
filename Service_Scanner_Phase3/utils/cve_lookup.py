# utils/cve_lookup.py
import os
import sqlite3
from config import NVD_DATA_DIR

DB_PATH = os.path.join(NVD_DATA_DIR, "nvd_vuln.db")

def find_cves_by_cpe(cpe_string=None, product=None, version=None, limit=20):
    if not cpe_string and not product:
        return []

    if not os.path.exists(DB_PATH):
        return []

    results = []
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # 1. CPE/Criteria 기반 검색
            if cpe_string:
                sql = """
                    SELECT DISTINCT c.id, c.description, c.cvss_score
                    FROM cve c
                    JOIN cve_cpe cp ON c.id = cp.cve_id
                    WHERE cp.criteria = ? AND cp.vulnerable = 1
                    ORDER BY c.cvss_score DESC LIMIT ?
                """
                cur.execute(sql, (cpe_string, limit))
                for r in cur.fetchall():
                    results.append({
                        "id": r["id"],
                        "title": r["description"][:100] + "..." if r["description"] else "No Desc",
                        "cvss": r["cvss_score"],
                        "href": f"https://nvd.nist.gov/vuln/detail/{r['id']}"
                    })

            # 2. 제품명 기반 LIKE 검색 (db_test.py 성공 로직)
            if not results and product:
                search_product = f"%{product}%"
                sql = """
                    SELECT DISTINCT c.id, c.description, c.cvss_score
                    FROM cve c
                    JOIN cve_cpe cp ON c.id = cp.cve_id
                    WHERE cp.product LIKE ? 
                    AND (cp.version = ? OR cp.version = '*' OR ? IS NULL)
                    AND cp.vulnerable = 1
                    ORDER BY c.cvss_score DESC LIMIT ?
                """
                cur.execute(sql, (search_product, version, version, limit))
                for r in cur.fetchall():
                    results.append({
                        "id": r["id"],
                        "title": r["description"][:100] + "..." if r["description"] else "No Desc",
                        "cvss": r["cvss_score"],
                        "href": f"https://nvd.nist.gov/vuln/detail/{r['id']}"
                    })
    except sqlite3.Error as e:
        print(f"[!] Local DB Error: {e}")

    return results