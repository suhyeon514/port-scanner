# README

## 프로젝트 개요
이 프로젝트는 네트워크 자산에 대한 포트 스캔을 수행하기 위한 구성 파일과 스크립트를 포함하고 있습니다. 다양한 스캔 프로파일과 포트 그룹 설정을 통해 외부 및 내부 자산에 대해 효율적이고 맞춤화된 스캔을 수행할 수 있습니다.

---

## 파일 설명

### 1. profiles.yaml
- **역할**: 스캔 프로파일을 정의하는 YAML 파일입니다. 각 프로파일은 특정 스캔 목적에 맞게 설정되어 있습니다.
- **구조**:
  - `profiles`: 각 프로파일의 이름, 설명, 기본 타겟 설정, nmap 정책 등이 포함됩니다.
  - 예:
    - `ext_discovery`: 외부 자산용 빠른 스캔 프로파일
    - `int_discovery`: 내부 자산용 스캔 프로파일
    - `discovery_1k`: 1-1024 포트 범위의 강화된 스캔 프로파일

### 2. port_groups.yaml
- **역할**: 포트 그룹 및 포트 세트를 정의하는 YAML 파일입니다. 각 그룹은 특정 서비스 유형(예: 웹, 데이터베이스, 원격 관리 등)에 해당하는 포트 번호를 포함합니다.
- **구조**:
  - `tcp_groups`: TCP 포트 그룹 정의
  - `udp_groups`: UDP 포트 그룹 정의
  - `tcp_sets`: TCP 포트 세트 정의 (예: 1-1024 범위)

### 3. profiles_loader.py
- **역할**: 스캔 프로파일을 실행하는 Python 스크립트입니다.
- **동작**:
  1. 명령줄 인자를 통해 실행할 프로파일과 타겟을 입력받습니다.
  2. `run_profile` 함수를 호출하여 스캔을 수행합니다.
  3. 스캔 완료 후, 추가적인 딥 스캔을 수행하기 위해 `deep_scan/bridge.py`를 실행합니다.

### 4. port_groups_loader.py
- **역할**: `profiles.yaml`과 `port_groups.yaml` 파일을 로드하고, 특정 프로파일에 따라 스캔할 포트 목록을 생성하는 Python 스크립트입니다.
- **동작**:
  1. `build_port_list` 함수는 프로파일과 포트 그룹 설정을 기반으로 스캔할 포트 목록을 생성합니다.
  2. 포함할 그룹과 세트를 처리하고, 제외할 그룹을 필터링하여 최종 포트 목록을 반환합니다.

---

## 실행 방법

1. **프로파일 실행**:
   ```bash
   python profiles_loader.py --profile <프로파일 이름> --targets <타겟 IP/도메인>
   ```
   - 예: 외부 자산 스캔
     ```bash
     python profiles_loader.py --profile ext_discovery --targets 192.168.1.1
     ```

2. **포트 목록 생성**:
   - `port_groups_loader.py`를 사용하여 특정 프로파일에 대한 포트 목록을 생성할 수 있습니다.

---

## 주요 의존성
- Python 3.8 이상
- `yaml` 라이브러리
- nmap (네트워크 스캔 도구)

---

## 디렉토리 구조
```
config/
├── profiles.yaml          # 스캔 프로파일 정의
├── port_groups.yaml       # 포트 그룹 및 세트 정의
├── profiles_loader.py     # 프로파일 실행 스크립트
├── port_groups_loader.py  # 포트 목록 생성 스크립트
└── __pycache__/           # Python 캐시 파일
```