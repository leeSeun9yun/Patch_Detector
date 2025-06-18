# Patch_Detector

## 개념 및 요약
Patch_Detector.py는 IDA Python 기반의 Security Patch 탐지 자동화 스크립트입니다.
탐지된 Security Patch는 주석을 통해서서 사용자에게 패치정보가 제공되며, 요약된 보고서가 생성됩니다.
---
## 기능개요
Patch_detector.py는 보안 패턴 기반의 탐지, 명령어 흐름 기반의 보안 로직 탐지, 예외처리 및 보안 관련 함수 호출 여부로 다음과 같은 보안 패치를 탐지합니다.
- stack 보호 
- 정수 오버플로우
- Control Flow Guard, Return Flow Guard 
- 예외 처리 함수 호출
- 보안 관련 함수 사용
    - SafeInt관련 함수
    - 보안 API 등
- 입력 길이 검사 및 NULL 검사


## 사용방법
Patch_detector.py 다운로드 후,
1. IDA로 Windows System Binary 열기
2. [File] -> [Script File] -> Patch_detector.py 선택 후 열기
