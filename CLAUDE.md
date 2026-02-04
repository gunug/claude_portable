# CLAUDE.md

## 언어 설정
- 모든 응답은 한국어로 작성 (영어 고유명사, 프로그래밍 용어 제외)

## 프로젝트 개요
Python + aiohttp 기반 WebSocket 채팅 서버. tkinter GUI로 설정 관리.

## 핵심 파일
| 파일 | 설명 |
|------|------|
| `server.py` | 메인 서버 + GUI (약 2800줄) |
| `index.html` | 웹 클라이언트 (로그인/채팅 UI) |
| `config.json` | 설정 파일 (Git 제외) |
| `project.md` | 아키텍처 상세 문서 |
| `README.md` | 프로젝트 소개 |
| `security_analysis.md` | 보안 분석 내역 |
| `migration_todo.md` | 마이그레이션 작업 목록 |

## 기술 스택
- **Backend**: Python, aiohttp (비동기)
- **GUI**: tkinter
- **보안**: bcrypt, secrets (세션 토큰)
- **Frontend**: HTML, JavaScript, WebSocket

## 주요 기능
- WebSocket 실시간 통신
- bcrypt 비밀번호 해시 + 세션 토큰 인증
- Brute Force 방어 (IP 차단/자동해제/영구차단)
- GUI 관리 패널 (계정, 보안, IP 관리)
- 다크 테마 웹 클라이언트

## 실행 방법
```bash
pip install -r requirements.txt
python server.py
# 또는: run.bat
```

## 외부 접속
ngrok으로 HTTPS 터널링: `ngrok http 8765`

## 코드 수정 시 주의사항
- `server.py`는 tkinter 메인 루프와 asyncio 이벤트 루프가 별도 스레드에서 동작
- WebSocket 토큰은 URL 파라미터가 아닌 연결 후 메시지로 전송
- 민감 파일(`config.json`, `blocked_ips.json`, `login_log.json`)은 Git 제외

## 관련 문서
- 상세 아키텍처: `project.md`
- 보안 분석: `security_analysis.md`
- 마이그레이션: `migration_todo.md`
