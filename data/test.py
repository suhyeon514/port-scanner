import sqlite3

DB_PATH = "nvd_vuln.db"

def search_vulnerabilities_by_cpe(cpe):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    print(f"\n[*] Searching vulnerabilities for CPE: {cpe}")
    cur.execute("""
        SELECT DISTINCT c.id, c.description, c.cvss_score, cp.criteria
        FROM cve c
        JOIN cve_cpe cp ON c.id = cp.cve_id
        WHERE cp.criteria = ?
    """, (cpe,))
    
    rows = cur.fetchall()
    for r in rows:
        print(f" >> CVE ID: {r['id']}")
        print(f"    Description: {r['description']}")
        print(f"    CVSS Score: {r['cvss_score']}")
        print(f"    CPE Criteria: {r['criteria']}\n")
    
    conn.close()

# Example usage
if __name__ == "__main__":
    cpe_to_search = "cpe:2.3:a:redislabs:redis:5.0.7:*:*:*:*:*:*:*"
    search_vulnerabilities_by_cpe(cpe_to_search)