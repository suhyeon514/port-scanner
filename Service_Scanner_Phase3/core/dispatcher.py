# core/dispatcher.py
from Service_Scanner_Phase3.Service_Scanner_Phase3.config import NSE_MAPPING
import re

def get_scripts_for_service(service_name):
    """
    서비스 이름을 분석하여 실행할 NSE 스크립트 목록을 반환합니다.
    """
    if not service_name or service_name == 'unknown':
        return NSE_MAPPING.get('default', 'banner')

    service_name = service_name.lower()
    selected_scripts = ""

    # 1. 정적 매핑 및 키워드 매칭
    if service_name in NSE_MAPPING:
        selected_scripts = NSE_MAPPING[service_name]
    else:
        for key in NSE_MAPPING:
            if key != 'default' and key in service_name:
                selected_scripts = NSE_MAPPING[key]
                break
    
    # 2. 매핑 실패 시 동적 생성 또는 기본값
    if not selected_scripts:
        if any(kw in service_name for kw in ['ssl', 'tls']):
            selected_scripts = NSE_MAPPING.get('https', 'ssl-cert')
        elif re.match(r'^[a-zA-Z0-9-]+$', service_name):
            return f"({service_name}-* and (default or version or safe)) or banner"
        else:
            selected_scripts = NSE_MAPPING.get('default', 'banner')

    # 3. 중복 제거 및 banner 강제 포함 로직
    script_list = [s.strip() for s in selected_scripts.split(',') if s.strip()]
    if 'banner' not in script_list:
        script_list.append('banner')
        
    return ",".join(script_list)
