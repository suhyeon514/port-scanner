from scapy.all import *
import random
import logging

# 스카피 로깅 레벨 조절 (경고 메시지 숨김)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class ScapyInferenceEngine:
    def __init__(self, timeout=1.5):
        self.timeout = timeout

    def run_tests(self, ip, port):
        """3가지 정밀 스캔 실시"""
        return {
            "ack_test": self.test_ack_scan(ip, port),
            "syn_ack_test": self.test_syn_ack_scan(ip, port),
            "reserved_test": self.test_reserved_bits_full(ip, port)
        }

    def test_ack_scan(self, ip, port):
        """연결 없는 ACK 패킷에 대한 반응 확인"""
        pkt = IP(dst=ip)/TCP(dport=port, flags="A")
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if resp is None: return "no-response"
        if resp.haslayer(TCP): return "rst-returned"
        if resp.haslayer(ICMP): return f"icmp-type-{resp.getlayer(ICMP).type}"
        return "unknown"

    def test_syn_ack_scan(self, ip, port):
        """예고 없는 SYN-ACK 패킷에 대한 반응 확인"""
        pkt = IP(dst=ip)/TCP(dport=port, flags="SA")
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        return "responded" if resp else "no-response"

    def test_reserved_bits_full(self, ip, port):
        """0~7번 예약 비트 변조 패킷에 대한 반응 확인"""
        results = {}
        for i in range(8):
            pkt = IP(dst=ip)/TCP(dport=port, flags="S", reserved=i)
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            results[i] = "pass" if resp else "drop"
        return results
