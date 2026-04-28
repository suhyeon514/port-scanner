# Service_Scanner_Phase1_2

## 프로젝트 개요

이 프로젝트는 네트워크 자산에 대한 포트 스캔을 수행하고, 심층 분석을 통해 보안 정책을 추론하는 Python 기반 도구입니다. 주요 구성 요소는 Nmap 스캔, 결과 분석, 심층 테스트 및 JSON 리포트 생성으로 이루어져 있습니다.

---

## 디렉토리 구조

```
Service_Scanner_Phase1_2/
├── config/
│   ├── port_groups_loader.py
│   ├── port_groups.yaml
│   ├── profiles_loader.py
│   ├── profiles.yaml
│   ├── README.md
│   └── __pycache__/
├── core/
│   ├── nmap_parser.py
│   ├── nmap_report.py
│   ├── nmap_runner.py
│   ├── orchestrator.py
│   ├── README.md
│   └── __pycache__/
├── deep_scan/
│   ├── bridge.py
│   ├── README.md
│   └── core/
│       ├── logic.py
│       ├── scapy_engine.py
│       └── __pycache__/
└── runs/
    ├── 2026-03-07T19-41-32+0900_discovery_1k_final_report.json
    ├── 2026-03-07T19-41-32+0900_discovery_1k_phase1_192.168.116.141.json
    ├── 2026-03-07T19-41-32+0900_discovery_1k_phase1_192.168.116.141.xml
    └── ...
```

---

## 주요 폴더 및 파일 설명

### 1. `config/`

이 폴더는 스캔 프로파일과 포트 그룹 설정을 관리하는 구성 파일과 스크립트를 포함합니다.

#### 파일 설명

- **`profiles.yaml`**: 스캔 프로파일 정의 파일. 각 프로파일은 특정 스캔 목적에 맞게 설정됩니다.
- **`port_groups.yaml`**: 포트 그룹 및 세트 정의 파일. 특정 서비스 유형에 해당하는 포트 번호를 포함합니다.
- **`profiles_loader.py`**: 스캔 프로파일을 실행하는 Python 스크립트.
- **`port_groups_loader.py`**: 프로파일과 포트 그룹 설정을 기반으로 스캔할 포트 목록을 생성하는 Python 스크립트.

#### 실행 방법

1. **프로파일 실행**:
   ```bash
   python profiles_loader.py --profile <프로파일 이름> --targets <타겟 IP/도메인>
   ```
2. **포트 목록 생성**:
   ```bash
   python port_groups_loader.py
   ```

---

### 2. `core/`

이 폴더는 Nmap 스캔 실행, 결과 파싱 및 리포트 생성을 담당하는 스크립트를 포함합니다.

#### 파일 설명

- **`nmap_parser.py`**: Nmap의 XML 출력 결과를 JSON 형식으로 변환하는 파서.
- **`nmap_report.py`**: 1차 및 2차 스캔 데이터를 병합하여 최종 리포트를 생성.
- **`nmap_runner.py`**: Nmap 스캔을 실행하고 결과를 처리.
- **`orchestrator.py`**: Nmap 스캔을 실행하기 위한 CLI 인터페이스 제공.

#### 파일 간 상호 관계

1. **`orchestrator.py`**는 사용자 입력을 받아 **`nmap_runner.py`**를 호출하여 스캔을 실행합니다.
2. **`nmap_runner.py`**는 Nmap 스캔을 실행하고 결과(XML)를 **`nmap_parser.py`**를 통해 JSON으로 변환합니다.
3. **`nmap_runner.py`**는 1차 및 2차 스캔 데이터를 **`nmap_report.py`**로 전달하여 최종 리포트를 생성합니다.

---

### 3. `deep_scan/`

이 폴더는 Nmap 스캔 결과를 기반으로 심층 분석을 수행하는 스크립트를 포함합니다.

#### 파일 설명

- **`bridge.py`**: Nmap 스캔 결과를 읽고 심층 분석을 수행한 후 결과를 JSON 파일로 저장.
- **`core/scapy_engine.py`**: Scapy를 사용하여 네트워크 패킷을 생성하고 전송하며, 원시 응답 데이터를 수집.
- **`core/logic.py`**: 포트 상태와 원시 응답 데이터를 기반으로 보안 정책을 추론.

#### 코드 동작 흐름

1. **Nmap 결과 파일 읽기**: `runs` 폴더에서 최신 `_final_report.json` 파일을 검색.
2. **Scapy를 통한 심층 테스트**: 다양한 네트워크 패킷 테스트를 수행하여 포트 상태를 분석.
3. **추론 로직 수행**: 수집된 데이터를 기반으로 보안 정책을 추론.
4. **결과 저장**: 분석 결과를 JSON 파일로 저장.

#### 실행 방법

1. `bridge.py`를 실행:
   ```bash
   python bridge.py
   ```
2. 결과 JSON 파일 확인: `runs/open_ports.json`.

---

### 4. `runs/`

이 폴더는 Nmap 스캔 결과 및 심층 분석 결과를 저장합니다. 파일명은 실행 시간과 타겟 정보를 포함합니다.

---

## 주요 의존성

- Python 3.8 이상
- `yaml` 라이브러리
- `scapy`
- Nmap (네트워크 스캔 도구)

---

## 주의사항

- `runs` 폴더에 `_final_report.json` 파일이 존재해야 합니다. 이 파일은 Nmap 스캔 결과를 포함해야 합니다.
- Python 3.6 이상이 필요합니다.