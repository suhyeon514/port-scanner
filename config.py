# config.py
import os

# --- 시스템 설정 ---
MAX_WORKERS = 4  # 동시에 분석할 포트(스레드) 개수
TIMEOUT = 350  # 각 포트별 최대 스캔 시간 (초)

# config.py
NMAP_STABLE_ARGS = "-Pn -T3 --max-retries 3 --open"
NMAP_SCRIPT_TIMEOUT = 180
NMAP_VERSION_SCAN_ARGS = "-sV --version-all"


# --- [Vulners API 설정] ---
# 환경변수 VULNERS_API_KEY가 있으면 사용, 없으면 빈 문자열 (API 비활성화)
# 보안을 위해 하드코딩된 키 제거 -> 환경변수 또는 빈 값 사용 권장
# VULNERS_API_KEY = os.getenv("VULNERS_API_KEY", "")
VULNERS_API_KEY = "R0DZ9RNH8QW1K2VJ2XPQ1VIECN0CHLX6GW9L6OA1AO1D9XMTE9P8SBE1OV8SJ7VS"
NVD_API_KEY="fc3bb526-cb2f-4786-af2e-1da3cb828a17"
# --- [Local NVD 설정] ---
# API 실패 시 사용할 로컬 NVD 데이터 폴더 경로 (현재 디렉토리의 data 폴더)
NVD_DATA_DIR = os.path.join(os.getcwd(), "data")

# --- NSE 스크립트 매핑 테이블 (핵심 전략) ---
# 서비스명(Key)에 따라 실행할 NSE 스크립트(Value)를 지정합니다.
NSE_MAPPING = {
    # --- [Web Service] ---
    'http': 'http-title,http-headers,http-methods,http-server-header,http-enum',
    'https': 'ssl-cert,http-title,http-headers,http-methods,http-enum',
    'http-alt': 'http-title,http-headers,http-methods',
    'ssl/http': 'ssl-cert,http-title,http-headers',

    # --- [Infrastructure] ---
    'ssh': 'ssh2-enum-algos,ssh-hostkey,ssh-auth-methods', # auth-methods 추가
    'ftp': 'ftp-anon,ftp-syst,ftp-vsftpd-backdoor', # vsftpd 백도어 체크 추가
    'telnet': 'telnet-encryption,telnet-ntlm-info',
    'rdp': 'rdp-enum-encryption,rdp-ntlm-info',
    
    # --- [Database] ---
    'mysql': 'mysql-info,mysql-empty-password,mysql-users,mysql-variables',
    'postgresql': 'pgsql-info,pgsql-version',
    'mssql': 'ms-sql-info,ms-sql-config,ms-sql-dump-hashes',
    'mongodb': 'mongodb-info,mongodb-databases',
    'redis': 'redis-info',
    
    # --- [Mail] ---
    'smtp': 'smtp-commands,smtp-open-relay,smtp-enum-users',

    # --- [DNS] ---
    'domain': 'dns-service-discovery,dns-recursion,dns-nsid',

    # --- [RPC & NFS] (기존 누락 보완) ---
    'rpcbind': 'rpcinfo',  # 111번 포트 필수
    'nfs': 'nfs-showmount,nfs-ls', # 2049번 포트

    # --- [Samba / NetBIOS] ---
    'netbios-ssn': 'smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode',
    'microsoft-ds': 'smb-os-discovery,smb-enum-shares,smb-security-mode',

    # --- [Backdoors & Remote Shells] (기존 누락 보완) ---
    'bindshell': 'banner', # 1524번은 배너가 곧 정보임
    'java-rmi': 'rmi-dumpregistry', # 1099번 RMI 레지스트리 확인
    
    # --- [IRC] ---
    'irc': 'irc-info,irc-unrealircd-backdoor',

    
    # --- [SSL IRC] (6697) ---
    'irc-ssl': 'irc-info,irc-unrealircd-backdoor',

    # --- [Legacy Unix] (512~514) ---
    # r-services는 응답이 없으면 스크립트 결과가 안 나오는 게 정상임.
    # banner를 같이 돌리도록 엔진을 수정했으므로 여기선 핵심만 지정.
    'exec': 'rlogin-auth', 
    'login': 'rlogin-auth',
    'shell': 'rlogin-auth',
    
    # ✅ distccd (3632) — 유명 취약점 스크립트
    'distccd': 'distcc-cve2004-2687',

        # ✅ VNC (5900)
    'vnc': 'vnc-info,vnc-title',

    # ✅ X11 (6000)
    'x11': 'x11-access',

    # ✅ AJP (8009)
    'ajp13': 'ajp-auth',

    # ✅ CUPS/IPP (631 or 9631 등, http로 인식 안 될 경우 대비)
    'ipp': 'cups-info',

    # ✅ PPP (3000 등)
    # Nmap 기본 테이블에서 3000번을 ppp로 인식하지만, 실제로는 대부분 HTTP(Node.js/React)입니다.
    'ppp': 'http-title,http-headers,http-methods,http-enum,banner',

    # ✅ Ruby DRb (8787) — 실제 스크립트 이름 확인 후 교체
    # 예시: 'drb': 'druby-info'
    # 우선은 기본값에 맡기고, 실제 NSE 스크립트 이름 확인 뒤 추가하는 게 안전
    
    # Default
    # 'default': 'banner'
    # # Default
    'default': 'banner, safe'  # 모르는 서비스는 더 적극적으로 탐색

}