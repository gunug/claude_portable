# Chat Socket → Claude Portable 이식 계획

## 개요

chat_socket의 Claude Code CLI 연동 및 웹 UI를 claude_portable에 이식하여, 인증 시스템이 포함된 완전한 웹 기반 Claude 채팅 서버를 구축합니다.

### 현재 상태 비교

| 기능 | claude_portable | chat_socket |
|------|-----------------|-------------|
| 인증 시스템 | ✅ 로그인, 세션, 토큰 | ❌ 없음 |
| Brute Force 방어 | ✅ IP 차단, Rate Limiting | ❌ 없음 |
| CORS | ✅ 미들웨어 | ❌ 없음 |
| Claude CLI 연동 | ❌ 없음 | ✅ 스트리밍 |
| 채팅 UI | ❌ 기본만 | ✅ 완성됨 |
| 요청 큐 | ❌ 없음 | ✅ 다중 사용자 |
| 사용량 모니터링 | ❌ 없음 | ✅ ccusage |
| PWA | ❌ 없음 | ✅ 지원 |
| GUI 설정 | ✅ tkinter | ❌ 없음 |

---

## Phase 1: Claude CLI 연동 (server.py)

### 1.1 전역 상태 추가
- [ ] `claude_processing` 플래그 추가
- [ ] `session_id` (Claude 세션) 추가
- [ ] `request_queue` (요청 대기열) 추가

### 1.2 Claude CLI 함수 이식
- [ ] `run_claude_stream()` - CLI 스트리밍 실행 (스레드)
- [ ] `ask_claude()` - Claude 응답 처리
- [ ] `test_claude_cli()` - CLI 연결 테스트
- [ ] `reset_session()` - 세션 리셋

### 1.3 사용량 조회 함수 이식
- [ ] `get_claude_usage()` - 일일 사용량 (ccusage)
- [ ] `get_claude_blocks()` - 5시간 블록 사용량

### 1.4 유틸리티 함수 이식
- [ ] `broadcast()` - 모든 클라이언트에 메시지 전송
- [ ] `send_progress()` - 진행 상황 브로드캐스트
- [ ] `get_relative_path()` - 경로 변환

### 1.5 설정 항목 추가
- [x] `claude_timeout` - Claude 응답 타임아웃 ✅
- [x] `claude_working_dir` - 작업 디렉토리 ✅
- [x] `claude_skip_permissions` - 권한 스킵 여부 ✅
- [ ] `USD_TO_KRW` - 환율 (사용량 표시용)

---

## Phase 2: WebSocket 핸들러 수정 (server.py)

### 2.1 메시지 타입 추가
- [x] `chat` - 채팅 메시지 처리 ✅
- [x] `usage` - 사용량 조회 요청 ✅
- [x] `reset` - 세션 리셋 요청 ✅
- [x] `queue_status` - 큐 상태 조회 ✅

### 2.2 인증 후 채팅 처리
- [x] 기존 인증 로직 유지 ✅
- [x] 인증 완료 후 채팅 메시지 처리 추가 ✅
- [x] 큐 시스템 연동 ✅

### 2.3 브로드캐스트 로직
- [x] 인증된 클라이언트만 브로드캐스트 ✅
- [x] 토큰별 연결 관리 활용 ✅

---

## Phase 3: 웹 UI 이식 (index.html)

### 3.1 CSS 이식
- [ ] 채팅 메시지 스타일 (user/assistant/system)
- [ ] 진행 상황 UI 스타일
- [ ] 사용량 패널 스타일
- [ ] 대기열 UI 스타일
- [ ] 반응형 스타일 (@media)

### 3.2 HTML 구조 추가
- [ ] 사용량 패널 (헤더 영역)
- [ ] 대기열 컨테이너
- [ ] 채팅 메시지 영역 (스크롤)
- [ ] 입력 영역 (textarea + 전송 버튼)

### 3.3 JavaScript 이식
- [ ] 메시지 전송 로직
- [ ] 메시지 수신 및 렌더링
- [ ] 진행 상황 UI 업데이트
- [ ] 사용량 UI 업데이트
- [ ] 대기열 UI 업데이트
- [ ] 마크다운 렌더링 (marked.js)
- [ ] 자동 스크롤

### 3.4 기존 인증 UI 유지
- [ ] 로그인 화면 유지
- [ ] 로그인 성공 시 채팅 화면 전환
- [ ] 로그아웃 버튼 유지

---

## Phase 4: PWA 지원 (선택)

### 4.1 PWA 파일 추가
- [ ] `manifest.json` 이식
- [ ] `service-worker.js` 이식
- [ ] `icons/` 폴더 이식

### 4.2 HTTP 핸들러 추가
- [ ] `/manifest.json` 엔드포인트
- [ ] `/service-worker.js` 엔드포인트
- [ ] `/icons/*` 엔드포인트

### 4.3 HTML 메타 태그 추가
- [ ] PWA 메타 태그
- [ ] 앱 아이콘 링크

---

## Phase 5: 추가 기능

### 5.1 GUI 확장 (tkinter)
- [x] Claude CLI 설정 프레임 추가 ✅
  - [x] 응답 타임아웃 설정
  - [x] 작업 디렉토리 설정 (폴더 선택)
  - [x] 권한 스킵 옵션 (--dangerously-skip-permissions)
- [x] Claude CLI 상태 확인 버튼 ✅
  - [x] CLI 설치 여부 확인
  - [x] CLI 버전 표시
- [ ] 현재 세션 ID 표시 (CLI 연동 후)
- [ ] 요청 큐 상태 표시 (CLI 연동 후)
- [ ] 사용량 표시 (CLI 연동 후)

### 5.2 배치 파일 업데이트
- [ ] `run.bat` 수정 (필요시)
- [ ] ngrok 관련 스크립트 추가 (선택)

---

## 의존성 추가

### requirements.txt 업데이트
```
aiohttp>=3.9.0
bcrypt>=4.0.0
# marked.js는 CDN 사용
```

### npm (선택)
```
npx ccusage@latest  # 사용량 조회용
```

---

## 파일 변경 예상

| 파일 | 변경 내용 |
|------|-----------|
| `server.py` | Claude CLI 연동 함수 추가, WebSocket 핸들러 확장 |
| `index.html` | 채팅 UI, 진행 상황 UI, 사용량 UI 추가 |
| `requirements.txt` | 변경 없음 (aiohttp 이미 포함) |
| `manifest.json` | 신규 (PWA) |
| `service-worker.js` | 신규 (PWA) |
| `icons/` | 신규 폴더 (PWA 아이콘) |

---

## 주의사항

1. **인증 시스템 유지**: chat_socket의 기능을 추가할 때 기존 인증 로직 손상 주의
2. **보안 유지**: Claude CLI 실행 시 입력 검증 필요
3. **세션 분리**: 로그인 세션과 Claude 세션은 별도 관리
4. **에러 처리**: Claude CLI 타임아웃, 연결 오류 등 처리 필요

---

## 예상 작업 순서

```
1. Phase 1 (CLI 연동) ─────────────────────────┐
2. Phase 2 (WebSocket 수정) ───────────────────┤ 필수
3. Phase 3 (웹 UI) ────────────────────────────┘
4. Phase 4 (PWA) ──────────────────────────────── 선택
5. Phase 5 (GUI 확장) ─────────────────────────── 선택
```

---

## 참고 문서

- [chat_socket/project.md](../chat_socket/project.md) - 원본 프로젝트 분석
- [security_analysis.md](./security_analysis.md) - 보안 분석
- [project.md](./project.md) - 현재 프로젝트 구조
