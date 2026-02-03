# Claude Portable 보안 분석

## 분석 대상
- server.py (v2.0)
- index.html (v2.0)
- config.json

---

## TODO 체크리스트

| 상태 | 취약점 | 등급 | 비고 |
|:----:|--------|------|------|
| ✅ | 세션 토큰 만료 | High | `server.py:427-434, 512-515` |
| ✅ | Brute Force 방어 (Rate Limiting) | High | `server.py:314-363, 398-461` |
| ✅ | Username Enumeration 방지 | Medium | `server.py:448, 457` |
| ✅ | 로그아웃 시 서버 세션 삭제 | Medium | `server.py:464-494` |
| ✅ | HTTPS 적용 | Critical | 내부망: HTTP, 외부망: ngrok (HTTPS) |
| ✅ | WebSocket 토큰 URL 노출 | Medium | 연결 후 첫 메시지로 토큰 전송 |
| ✅ | config.json 파일 권한 | Low | 개인 PC 환경 실질적 위험 없음, 전용 계정 사용 권장 |
| ✅ | CORS 설정 | Low | 커스텀 미들웨어로 Origin 검증 |

---

## 위험 등급 정의

| 등급 | 설명 |
|------|------|
| **Critical** | 즉시 악용 가능, 시스템 전체 침해 위험 |
| **High** | 민감 정보 노출 또는 인증 우회 가능 |
| **Medium** | 제한적 공격 가능, 다른 취약점과 연계 시 위험 |
| **Low** | 정보 수집에 활용 가능, 직접적 위험 낮음 |

---

## 발견된 취약점

### 1. ~~HTTPS 미사용 (평문 통신)~~ ✅ 해결됨 (운영 정책)
**등급: Critical**

**위치**: `server.py:585`
```python
site = web.TCPSite(self.runner, self.host, self.port)
```

**운영 정책**:
| 환경 | 프로토콜 | 설명 |
|------|----------|------|
| 내부망 | HTTP | 신뢰할 수 있는 네트워크, 평문 통신 허용 |
| 외부망 | HTTPS (ngrok) | 포트포워딩 미사용, ngrok 터널링으로 HTTPS 자동 적용 |

**ngrok 사용 시 보안**:
- ngrok은 클라이언트 ↔ ngrok 서버 구간을 TLS로 암호화
- 외부 사용자는 `https://*.ngrok.io` 주소로 접속
- 로컬 서버(HTTP) ↔ ngrok 클라이언트 구간은 localhost이므로 안전

**결론**:
- 내부망: 동일 네트워크 내 신뢰된 환경에서만 사용
- 외부망: ngrok을 통해 HTTPS가 적용되므로 평문 통신 문제 해결

---

### 2. ~~세션 토큰 만료 없음~~ ✅ 해결됨
**등급: High**

**해결 내용**:
- 세션 구조 개선: `sessions[token] = {"id": user_id, "created_at": timestamp, "expires_at": timestamp}` (`server.py:15-16, 427-434`)
- 설정에 `session_timeout` 추가 (기본 3600초, `server.py:49`)
- WebSocket 연결 시 세션 만료 확인 (`server.py:512-515`)
- GUI에서 세션 만료 시간 설정 가능 (`server.py:917-922`)

---

### 3. ~~로그인 시도 제한 없음 (Brute Force)~~ ✅ 해결됨
**등급: High**

**해결 내용**:
- IP별 로그인 시도 기록 (`server.py:22-23`)
- 설정 항목 추가 (`server.py:46-48`):
  - `max_login_attempts`: 최대 로그인 시도 (기본 5회)
  - `lockout_duration`: 차단 시간 (기본 300초)
  - `max_auto_unblock`: 최대 자동 해제 횟수 (초과 시 영구 차단)
- IP 차단/해제 관리 기능 (`server.py:71-200`)
- 로그인 로그 기록 (`server.py:202-288`)
- Brute Force 방어 로직 (`server.py:314-369`)
- GUI에서 IP 관리 및 로그 확인 가능 (`server.py:924-956`)

---

### 4. ~~계정 존재 여부 노출 (Username Enumeration)~~ ✅ 해결됨
**등급: Medium**

**해결 내용**:
- 비밀번호 오류와 계정 없음 모두 동일한 메시지 반환:
  - `server.py:448`: "아이디 또는 비밀번호가 올바르지 않습니다."
  - `server.py:457`: "아이디 또는 비밀번호가 올바르지 않습니다."

---

### 5. ~~로그아웃 시 서버 세션 미삭제~~ ✅ 해결됨
**등급: Medium**

**해결 내용**:
- POST /logout 엔드포인트 추가 (`server.py:464-494`)
- 로그아웃 시 서버에서 세션 및 WebSocket 연결 삭제
- 클라이언트에서 로그아웃 시 서버 API 호출 (`index.html:241-270`)

---

### 6. ~~WebSocket 토큰 URL 노출~~ ✅ 해결됨
**등급: Medium**

**해결 내용**:
- URL 쿼리 파라미터에서 토큰 제거
- WebSocket 연결 후 첫 메시지로 토큰 전송 방식으로 변경

**변경된 코드**:

`index.html` - 클라이언트:
```javascript
// 토큰 없이 연결
const wsUrl = `${protocol}//${host}/ws`;
ws = new WebSocket(wsUrl);

ws.onopen = () => {
    // 연결 후 토큰 인증 메시지 전송
    ws.send(JSON.stringify({ type: 'auth', token: authToken }));
};
```

`server.py` - 서버:
```python
# 첫 메시지로 토큰 검증
if auth_data.get("type") == "auth":
    token = auth_data.get("token")
    # 토큰 검증 후 연결 허용
```

**보안 효과**:
- 서버 액세스 로그에 토큰 미기록
- 브라우저 히스토리에 토큰 미노출
- Referer 헤더를 통한 토큰 유출 방지

---

### 7. config.json 파일 권한
**등급: Low** ✅ 현실적 위험 없음 (개인 PC 환경)

**위치**: `config.json`

**문제점 (이론적)**:
- bcrypt 해시된 비밀번호가 파일에 저장
- 파일 시스템 접근 권한 관리 없음

---

#### 현실적 위험도 재평가

**이 프로젝트의 보호 대상**:
```
외부 네트워크 → [웹 서버 인증] → 내 컴퓨터
                     ↑
               여기를 보호 (✅ 완료)
```

**config.json 공격 시나리오의 전제 조건**:

| 시나리오 | 전제 조건 | 현실적 평가 |
|----------|-----------|-------------|
| 동일 서버의 다른 사용자 | 공격자가 이미 내 컴퓨터에 접근 | ❌ **이미 침해된 상태** - config.json 이전에 더 큰 문제 |
| LFI 취약점 연계 | 다른 취약점이 존재해야 함 | ❌ 해당 취약점 없음 |
| Git 노출 | 개발자 실수로 커밋 | ✅ `.gitignore`로 방지됨 |

---

#### 결론: 개인 PC 환경에서 실질적 위험 없음

| 항목 | 설명 |
|------|------|
| **공격 전제** | 모든 시나리오가 "이미 컴퓨터 침해됨" 또는 "개발자 실수"를 전제 |
| **보호 대상** | 웹 서버 인증 → 이미 해결됨 (로그인, 세션, rate limiting, CORS) |
| **bcrypt 보호** | 설령 해시가 노출되어도 강한 비밀번호는 복원 불가 |
| **Git 노출 방지** | `.gitignore`에 민감 파일 추가됨 |

---

#### 추가 보호 조치

**1. 전용 계정 사용 권장**
- GUI 계정 추가 시 경고 메시지 표시
- "이 소프트웨어 전용 아이디/패스워드 사용" 안내

**2. 파일 권한 설정 (선택적, 공유 서버 환경)**
| OS | 명령어 |
|----|--------|
| Linux/macOS | `chmod 600 config.json` |
| Windows | `icacls config.json /inheritance:r /grant:r "%USERNAME%:F"` |

---

### 8. ~~CORS 설정 없음~~ ✅ 해결됨
**등급: Low**

**해결 내용**:
- 커스텀 CORS 미들웨어 구현 (추가 라이브러리 불필요)
- Origin 검증으로 허용된 도메인만 접근 가능

**허용된 Origin**:
| 유형 | 도메인 |
|------|--------|
| localhost | `http://localhost:{port}`, `http://127.0.0.1:{port}` |
| 로컬 IP | 서버가 0.0.0.0으로 바인딩 시 자동 감지 |
| ngrok | `*.ngrok.io`, `*.ngrok-free.app`, `*.ngrok.app`, `*.ngrok.dev` |

**구현 코드** (`server.py:572-625`):
```python
@web.middleware
async def cors_middleware(request, handler):
    origin = request.headers.get("Origin", "")

    # Origin 검증
    if not is_origin_allowed(origin):
        return web.Response(text="CORS policy: Origin not allowed", status=403)

    # Preflight 요청 처리 및 CORS 헤더 추가
    ...
```

**보안 효과**:
- 허용되지 않은 도메인에서의 API 호출 차단
- CSRF 공격 방어 강화

---

## 잘 구현된 보안 요소

| 항목 | 설명 |
|------|------|
| bcrypt 해시 | 비밀번호를 bcrypt로 안전하게 해시 (salt 포함) |
| secrets 모듈 | 암호학적으로 안전한 토큰 생성 |
| WebSocket 인증 | 토큰 검증 후 연결 허용 |
| 세션 만료 | 설정 가능한 세션 타임아웃 |
| Rate Limiting | IP 기반 로그인 시도 제한 |
| IP 차단 | 자동/수동 IP 차단 및 영구 차단 지원 |
| 로그인 로그 | 모든 로그인 시도 기록 |
| HTTPS (외부망) | ngrok 터널링으로 외부 접속 시 TLS 암호화 |
| WebSocket 토큰 보호 | URL 대신 연결 후 메시지로 토큰 전송 |
| CORS 정책 | Origin 검증으로 허용된 도메인만 접근 허용 |

---

## 우선순위 권장 조치

1. ~~**즉시**: Rate Limiting 구현 (Brute Force 방지)~~ ✅ 완료
2. ~~**즉시**: 에러 메시지 통일 (Username Enumeration 방지)~~ ✅ 완료
3. ~~**단기**: 세션 만료 구현~~ ✅ 완료
4. ~~**단기**: 로그아웃 API 추가~~ ✅ 완료
5. ~~**중기**: HTTPS 적용 (운영 환경)~~ ✅ 완료 (내부망 HTTP / 외부망 ngrok HTTPS)
6. ~~**중기**: WebSocket 토큰 전송 방식 개선~~ ✅ 완료
7. ~~**저위험**: config.json 파일 권한 설정~~ ✅ 완료 (개인 PC 환경 실질적 위험 없음)
8. ~~**저위험**: CORS 설정~~ ✅ 완료
