class DecisionLogic:
    @staticmethod
    def infer_policy(results, proto):
        """응답 결과를 바탕으로 보안 정책 및 거동 추정 (한글 출력)"""
        ack = results.get("ack_test")
        sak = results.get("syn_ack_test")
        res = results.get("reserved_test", {})
        
        # 1. 공통 무응답 분석
        if ack == "no-response" and sak == "no-response" and all(v == "drop" for v in res.values()):
            return {
                "conclusion": "강력한 정적/상태 기반 차단 정책",
                "reason": "모든 비정상 패킷에 대해 응답 없이 패킷을 폐기함. 보안 그룹이나 방화벽에 의해 명시적으로 DROP 되었을 가능성이 높음."
            }

        # 2. 프로토콜별 상세 추론
        if proto == "tcp":
            # 심층 패킷 검사(DPI) 징후 탐지
            if res.get(0) == "pass" and any(res[i] == "drop" for i in range(1, 8)):
                return {
                    "conclusion": "심층 패킷 검증(DPI) 작동 중",
                    "reason": "표준 패킷(0)은 허용하나, 비표준 예약 비트가 포함된 헤더를 탐지하여 선별적으로 차단하고 있음."
                }
            
            if ack == "rst-returned":
                return {
                    "conclusion": "표준 포트 닫힘 (방화벽 간섭 없음)",
                    "reason": "비정상 플래그에 대해 운영체제가 표준 RST 응답을 보냄. 중간에 패킷을 가로채는 보안 장비가 없거나 모든 패킷을 통과시키는 상태임."
                }

        elif proto == "udp":
            # UDP 포트인데 TCP 응답이 오는 경우
            if ack == "rst-returned" or sak == "responded":
                return {
                    "conclusion": "프로토콜 비의존적 통과 정책",
                    "reason": "UDP 포트임에도 TCP 변조 패킷이 호스트 스택까지 도달하여 OS가 응답함. 프로토콜별 세밀한 필터링이 적용되지 않은 상태임."
                }

        if "icmp" in ack:
            return {
                "conclusion": "명시적 거부 정책 (ICMP 반환)",
                "reason": "보안 장비나 라우터가 정책에 따라 패킷을 차단하고, 도달 불능 메시지를 친절하게 응답함."
            }

        return {
            "conclusion": "복합적 보안 정책 탐지",
            "reason": "일반적이지 않은 응답 패턴임. 특수한 보안 설정이나 네트워크 환경의 영향일 수 있음."
        }
