import argparse
import os

from core.nmap_runner import run_profile
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, help="Profile name to run")
    parser.add_argument("--targets", required=True, help="Target to scan")
    parser.add_argument("--no-second-pass", action="store_true", help="Skip second pass scan")
    args = parser.parse_args()
    
    result = run_profile(
        profile_name=args.profile,
        targets=args.targets,
        second_pass=not args.no_second_pass
    )
    
    print("\n[*] Starting Deep Scan (Policy Inference)...")
    os.system("python deep_scan/bridge.py") # 루트 경로에서 실행 기준

if __name__ == "__main__":
   
    main()