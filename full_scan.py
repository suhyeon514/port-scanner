# run_full_scan.py
import subprocess
import os
import sys
import glob

# 설정: Phase 1/2와 Phase 3의 폴더 이름이 정확한지 꼭 확인하세요!
DIR_PHASE1 = "Service_Scanner_Phase1_2"  # Phase 1/2 스캔이 실행되는 폴더
DIR_PHASE3 = "Service_Scanner_Phase3"  # Phase 3 스캔이 실행되는 폴더

# Python 명령어를 OS에 따라 설정
PYTHON_CMD = "python3" if os.name != "nt" else "python"  # Windows는 'python', 그 외는 'python3'

# Phase 1/2 실행 함수
def run_phase1(target_ip, profile):
    print(f"\n[*] --- Phase 1/2 시작: 타겟 {target_ip} (Profile: {profile}) ---")
    
    # Phase 1 실행 명령어 구성
    cmd = [
        PYTHON_CMD, "-m", "config.profiles_loader",  # OS에 따라 python 또는 python3 사용
        "--profile", profile,  # 스캔 프로필 지정
        "--targets", target_ip  # 타겟 IP 지정
    ]
    
    try:
        # Phase 1 폴더 내에서 명령어 실행 (cwd 옵션 사용)
        subprocess.run(cmd, cwd=DIR_PHASE1, check=True)
    except subprocess.CalledProcessError as e:
        # 명령어 실행 중 에러 발생 시 처리
        print(f"[!] Phase 1 실행 중 에러 발생: {e}")
        sys.exit(1)
        
    print("[*] Phase 1/2 완료.")

# Phase 1/2 결과 파일 검색 함수
def get_latest_report():
    """Phase 1의 runs 폴더에서 가장 최근에 생성된 _final_report.json 파일을 찾음"""
    runs_dir = os.path.join(DIR_PHASE1, "runs")  # Phase 1 결과 파일이 저장된 폴더
    
    # 파일 패턴 매칭 (*_final_report.json)
    search_pattern = os.path.join(runs_dir, "*_final_report.json")
    list_of_files = glob.glob(search_pattern)  # 패턴에 맞는 파일 목록 가져오기
    
    if not list_of_files:
        # 결과 파일이 없을 경우 에러 처리
        print(f"[!] {runs_dir} 경로에서 리포트 파일을 찾을 수 없습니다.")
        sys.exit(1)
    
    # 생성 시간 역순으로 정렬하여 가장 최근 파일 선택
    latest_file = max(list_of_files, key=os.path.getctime)
    
    # 절대 경로로 변환하여 반환
    abs_path = os.path.abspath(latest_file)
    print(f"[*] 최신 리포트 파일 감지됨: {abs_path}")
    return abs_path

# Phase 3 실행 함수
def run_phase3(report_path):
    print(f"\n[*] --- Phase 3 시작: 입력 파일 {os.path.basename(report_path)} ---")
    
    # Phase 3 실행 명령어 구성
    cmd = [
        PYTHON_CMD, "main_phase3.py",  # 윈도우라면 python, 리눅스면 python3
        report_path  # Phase 1/2 결과 파일 경로 전달
    ]
    
    try:
        # Phase 3 폴더 내에서 명령어 실행
        subprocess.run(cmd, cwd=DIR_PHASE3, check=True)
    except subprocess.CalledProcessError as e:
        # 명령어 실행 중 에러 발생 시 처리
        print(f"[!] Phase 3 실행 중 에러 발생: {e}")
        sys.exit(1)

    print("\n[*] === 모든 통합 스캔이 완료되었습니다. ===")

# 메인 실행부
if __name__ == "__main__":
    # 명령줄 인자 확인
    if len(sys.argv) < 2:
        print("사용법: python run_full_scan.py <Target-IP> [Profile_Name]")
        print("예시: python run_full_scan.py 192.168.150.13 discovery_1k")
        sys.exit(1)
        
    # 타겟 IP와 프로필 설정
    target = sys.argv[1]  # 첫 번째 인자는 타겟 IP
    profile = sys.argv[2] if len(sys.argv) > 2 else "discovery_1k"  # 두 번째 인자는 선택적 프로필 (기본값: discovery_1k)
    
    # 1. Phase 1 실행
    run_phase1(target, profile)
    
    # 2. Phase 1/2 결과 파일 자동 탐색
    report_file = get_latest_report()
    
    # 3. Phase 3 실행 (Phase 1/2 결과 파일을 인자로 전달)
    run_phase3(report_file)