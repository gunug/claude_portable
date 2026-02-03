# Claude Portable

Python 기반의 경량 WebSocket 채팅 서버입니다. tkinter GUI를 통해 설정을 관리하고 웹 클라이언트를 제공합니다.

## 주요 기능

- **WebSocket 실시간 통신**: aiohttp 기반 비동기 서버
- **GUI 관리 패널**: tkinter 기반 설정 및 모니터링
- **계정 인증**: bcrypt 해시 비밀번호, 세션 토큰
- **보안 시스템**: Brute Force 방어, IP 차단, 로그인 로그
- **웹 클라이언트**: 다크 테마 로그인/채팅 UI

## 기술 스택

| 구분 | 기술 |
|------|------|
| Backend | Python, aiohttp |
| GUI | tkinter |
| 보안 | bcrypt, secrets |
| Frontend | HTML, JavaScript, WebSocket |

## 설치 및 실행

```bash
# 의존성 설치
pip install -r requirements.txt

# 실행
python server.py

# 또는 Windows
run.bat
```

## 파일 구조

| 파일 | 설명 |
|------|------|
| `server.py` | 메인 서버 + GUI 애플리케이션 |
| `index.html` | 웹 클라이언트 |
| `config.json` | 설정 파일 (자동 생성, Git 제외) |
| `requirements.txt` | Python 의존성 |
| `run.bat` | Windows 실행 스크립트 |

## 보안 기능

### 구현된 보안 요소

| 기능 | 설명 |
|------|------|
| bcrypt 해시 | 비밀번호를 안전하게 해시 (salt 포함) |
| 세션 토큰 | secrets 모듈로 암호학적으로 안전한 토큰 생성 |
| 세션 만료 | 설정 가능한 세션 타임아웃 |
| Rate Limiting | IP 기반 로그인 시도 제한 |
| IP 차단 | 자동/수동 IP 차단 및 영구 차단 지원 |
| 로그인 로그 | 모든 로그인 시도 기록 |
| CORS 정책 | Origin 검증으로 허용된 도메인만 접근 |
| WebSocket 토큰 보호 | URL 대신 연결 후 메시지로 토큰 전송 |

### 인증 흐름

```
[로그인 폼] → POST /login (id, password)
     ↓
[서버] bcrypt 검증 → 세션 토큰 발급
     ↓
[클라이언트] WebSocket 연결 → 토큰 인증 메시지 전송
     ↓
[서버] 토큰 검증 → 연결 허용/거부
```

### Brute Force 방어

```
N회 로그인 실패 → IP 차단 (T초)
     ↓
시간 경과 → 자동 해제
     ↓
차단 M회 반복 → 영구 차단 (수동 해제만 가능)
```

## 외부 접속 (ngrok)

내부망에서는 HTTP로 동작하며, 외부 접속은 [ngrok](https://ngrok.com/)을 통해 HTTPS를 적용합니다.

```bash
ngrok http 8765
```

## 문서

- [보안 분석 상세](./security_analysis.md) - 보안 취약점 분석 및 해결 내역
- [프로젝트 상세](./project.md) - 아키텍처 및 설정 상세

## 주의사항

- `config.json`에 저장되는 계정 정보는 고수준으로 보호되지 않습니다
- **이 소프트웨어 전용 아이디와 패스워드를 별도로 지정하세요**
- 민감한 파일(`config.json`, `blocked_ips.json`, `login_log.json`)은 `.gitignore`에 포함되어 있습니다

## 라이선스

MIT License
