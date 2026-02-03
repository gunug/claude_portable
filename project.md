# Claude Portable

## 개요
Python 기반의 경량 WebSocket 채팅 서버로, tkinter GUI를 통해 설정을 관리하고 웹 클라이언트를 제공합니다.

## 기술 스택
- **Backend**: Python, aiohttp (비동기 HTTP/WebSocket)
- **GUI**: tkinter
- **보안**: bcrypt (비밀번호 해시), 세션 토큰, Brute Force 방어
- **프론트엔드**: HTML, JavaScript (WebSocket 클라이언트)

## 파일 구조

| 파일 | 설명 |
|------|------|
| `server.py` | 메인 서버 + GUI 애플리케이션 |
| `index.html` | 웹 클라이언트 (로그인 + WebSocket) |
| `config.json` | 설정 파일 (포트, 계정, 보안 설정) |
| `blocked_ips.json` | 차단된 IP 목록 (자동 생성) |
| `login_log.json` | 로그인 기록 (자동 생성) |
| `run.bat` | 실행 스크립트 |
| `requirements.txt` | Python 의존성 |
| `.gitignore` | Git 제외 파일 목록 |

## 주요 기능

### 서버 (server.py)

#### HTTP/WebSocket 엔드포인트
| 경로 | 메서드 | 설명 |
|------|--------|------|
| `/` | GET | index.html 제공 |
| `/login` | POST | 로그인 인증 (토큰 발급) |
| `/ws` | WebSocket | 실시간 통신 (토큰 필요) |

#### GUI 설정 패널
- **서버 설정**: 포트, 타임아웃
- **계정 설정**: 계정 추가/삭제
- **보안 설정**: 최대 로그인 시도, 차단 시간, 최대 자동 해제 횟수
- **IP 내역**: IP별 접속 통계, 수동 차단/해제, 로그 보기
- **UI 설정**: 자동 스크롤, 알림 소리
- **서버 제어**: 시작/중지

### 클라이언트 (index.html)
- 로그인 화면 (아이디/비밀번호)
- 로그인 성공 시 채팅 화면 전환
- WebSocket 연결 상태 표시
- 로그아웃 기능
- 다크 테마 UI

### 보안 시스템

#### 인증 흐름
```
[로그인 폼] → POST /login (id, password)
     ↓
[서버] bcrypt 검증 → 세션 토큰 발급
     ↓
[클라이언트] 토큰 저장 → WebSocket 연결 (/ws?token=xxx)
     ↓
[서버] 토큰 검증 → 연결 허용/거부
```

#### Brute Force 방어
```
N회 로그인 실패 → IP 차단 (T초)
     ↓
시간 경과 → 자동 해제 (시도 횟수 초기화)
     ↓
차단 M회 반복 → 영구 차단 (수동 해제만 가능)
```

#### 로그 기록
| 상태 | 설명 |
|------|------|
| 성공 | 로그인 성공 |
| 실패 | 로그인 실패 (비밀번호 오류/계정 없음) |
| 차단 | IP 차단됨 |
| 만료 | 차단 시간 만료로 자동 해제 |
| 해제 | 관리자 수동 해제 |

## 설정 항목 (config.json)

| 항목 | 기본값 | 설명 |
|------|--------|------|
| `port` | 8765 | 서버 포트 |
| `host` | 0.0.0.0 | 바인딩 주소 |
| `timeout` | 300 | 타임아웃 (초) |
| `auto_scroll` | true | 자동 스크롤 |
| `sound` | true | 알림 소리 |
| `accounts` | [] | 계정 목록 (id, bcrypt 해시 비밀번호) |
| `max_login_attempts` | 5 | 최대 로그인 시도 횟수 |
| `lockout_duration` | 300 | 차단 시간 (초) |
| `max_auto_unblock` | 3 | 최대 자동 해제 횟수 (초과 시 영구 차단) |

## 실행 방법

```bash
# 의존성 설치
pip install -r requirements.txt

# 실행
python server.py
# 또는
run.bat
```

## 아키텍처

```
[tkinter GUI] ─── 설정/IP관리 ───┐
                                 │
                                 v
[ServerThread] ─── aiohttp ─── [GET /] ─── index.html
     │                         [POST /login] ─── 인증
     │                         [WS /ws?token=] ─── WebSocket
     │
     └── asyncio event loop (별도 스레드)

[보안 시스템]
     ├── sessions {} ─── 세션 토큰 (메모리)
     ├── login_attempts {} ─── 로그인 시도 (메모리)
     ├── blocked_ips.json ─── 차단 IP (파일)
     └── login_log.json ─── 로그 기록 (파일)
```

## 보안 권장 설정

| 용도 | 최대 로그인 시도 | 차단 시간 | 최대 자동 해제 |
|------|-----------------|----------|---------------|
| 테스트 | 5회 | 10~30초 | 3회 |
| 운영 | 5회 | 300초 (5분) | 3회 |

**IP당 최대 시도 횟수**: (최대 로그인 시도) × (최대 자동 해제 + 1)
- 예: 5 × 4 = 20회 후 영구 차단

## TODO / 개선 사항
- [ ] 채팅 메시지 송수신 기능 구현
- [ ] 메시지 저장/기록 기능
- [ ] 다중 클라이언트 브로드캐스트
- [x] ~~로그인/인증 처리 연동~~
- [x] ~~Brute Force 방어~~
- [x] ~~IP 차단 관리~~
