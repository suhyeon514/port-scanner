# utils/logger.py
import logging
import os
from datetime import datetime

def setup_logger():
    """
    로깅 시스템을 초기화합니다.
    - logs 폴더가 없으면 생성
    - 파일명: logs/scan_YYYYMMDD_HHMMSS.log
    - 로그 레벨: DEBUG (모든 상세 정보 기록)
    """
    # 1. 로그 저장할 폴더 생성
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # 2. 파일명 생성 (예: logs/scan_20231025_143000.log)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"logs/scan_{timestamp}.log"

    # 3. 로거 설정
    # FileHandler: 파일에 기록
    # logging.basicConfig을 사용하여 루트 로거 설정
    logging.basicConfig(
        level=logging.DEBUG,  # 디버그 모드로 설정하여 모든 정보 기록
        format='%(asctime)s [%(levelname)s] [%(module)s] %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8')
            # StreamHandler는 추가하지 않음 (터미널 출력은 기존 print 유지)
        ]
    )

    return log_filename