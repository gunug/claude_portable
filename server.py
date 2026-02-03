import asyncio
import sys
import os
import json
import threading
import secrets
import time
import uuid
import subprocess
from datetime import datetime
from queue import Queue, Empty
from collections import deque
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from aiohttp import web
import bcrypt

# 세션 토큰 저장소 (메모리) - 로그인 세션
# {token: {"id": user_id, "created_at": timestamp, "expires_at": timestamp}}
sessions = {}

# 토큰별 WebSocket 연결 관리
# {token: websocket}
token_connections = {}

# 로그인 시도 기록 (메모리) - {ip: {"count": n, "first_attempt": timestamp}}
login_attempts = {}

# ============================================================
# Claude CLI 관련 전역 상태
# ============================================================

# Claude 처리 상태
claude_processing = False
current_stop_event = None
claude_session_id = None  # Claude 세션 ID (로그인 세션과 별도)
claude_session_started = False

# 요청 큐 관리
request_queue = deque()  # 대기 중인 요청 큐
queue_lock = asyncio.Lock()  # 큐 접근 동기화

# 환율 (사용량 표시용)
USD_TO_KRW = 1430

# Windows asyncio 호환성 (Python 3.14 미만에서만 필요)
if sys.platform == "win32" and sys.version_info < (3, 14):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# 현재 스크립트 디렉토리
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 실행 위치 (현재 작업 디렉토리) - config는 여기에 저장
WORKING_DIR = os.getcwd()
CONFIG_FILE = os.path.join(WORKING_DIR, "config.json")
BLOCKED_IPS_FILE = os.path.join(WORKING_DIR, "blocked_ips.json")
LOGIN_LOG_FILE = os.path.join(WORKING_DIR, "login_log.json")

# 기본 설정
DEFAULT_CONFIG = {
    "port": 8765,
    "host": "0.0.0.0",
    "timeout": 300,
    "auto_scroll": True,
    "sound": True,
    "accounts": [],
    "max_login_attempts": 5,
    "lockout_duration": 300,  # 초 (5분)
    "max_auto_unblock": 3,  # 최대 자동 해제 횟수 (초과 시 영구 차단)
    "session_timeout": 3600,  # 세션 만료 시간 (초, 기본 1시간)
    # Claude CLI 설정
    "claude_timeout": 300,  # Claude 응답 타임아웃 (초)
    "claude_working_dir": "",  # 작업 디렉토리 (빈 문자열 = 현재 디렉토리)
    "claude_skip_permissions": True  # --dangerously-skip-permissions 플래그 사용
}


def load_config():
    """설정 파일 로드 (없으면 기본값으로 생성)"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved_config = json.load(f)
                return {**DEFAULT_CONFIG, **saved_config}
        except:
            pass

    # config.json이 없으면 기본값으로 생성
    default_config = DEFAULT_CONFIG.copy()
    save_config(default_config)
    print(f"[설정] 기본 설정 파일 생성: {CONFIG_FILE}")
    return default_config


def save_config(config):
    """설정 파일 저장"""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


# ============================================================
# 차단 IP 관리
# ============================================================

def load_blocked_ips():
    """차단된 IP 목록 로드"""
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return {}


def save_blocked_ips(blocked_ips):
    """차단된 IP 목록 저장"""
    with open(BLOCKED_IPS_FILE, "w", encoding="utf-8") as f:
        json.dump(blocked_ips, f, indent=2, ensure_ascii=False)


def block_ip(ip, reason="Too many failed login attempts"):
    """IP 차단"""
    lockout_duration = config.get("lockout_duration", 300)
    max_auto_unblock = config.get("max_auto_unblock", 3)
    blocked_at = datetime.now()

    blocked_ips = load_blocked_ips()

    # 이전 차단 횟수 확인
    block_count = 1
    if ip in blocked_ips:
        block_count = blocked_ips[ip].get("block_count", 0) + 1

    # 최대 자동 해제 횟수 초과 시 영구 차단
    if block_count > max_auto_unblock:
        blocked_ips[ip] = {
            "blocked_at": blocked_at.isoformat(),
            "expires_at": None,  # 영구 차단
            "reason": reason,
            "block_count": block_count,
            "permanent": True,
            "active": True
        }
        save_blocked_ips(blocked_ips)
        add_login_log(ip, None, "blocked", f"{reason} (영구 차단 - {block_count}회 차단)")
        print(f"[영구 차단] {ip} 영구 차단됨: {reason} ({block_count}회 차단)")
    else:
        expires_at = blocked_at + __import__('datetime').timedelta(seconds=lockout_duration)
        blocked_ips[ip] = {
            "blocked_at": blocked_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "reason": reason,
            "block_count": block_count,
            "permanent": False,
            "active": True
        }
        save_blocked_ips(blocked_ips)
        expires_str = expires_at.strftime("%Y/%m/%d %H:%M:%S")
        add_login_log(ip, None, "blocked", f"{reason} ({expires_str}까지, {block_count}/{max_auto_unblock}회)")
        print(f"[차단] {ip} 차단됨: {reason} ({expires_str}까지, {block_count}/{max_auto_unblock}회)")


def unblock_ip(ip):
    """IP 차단 해제"""
    blocked_ips = load_blocked_ips()
    if ip in blocked_ips:
        del blocked_ips[ip]
        save_blocked_ips(blocked_ips)
        # 메모리의 시도 기록도 초기화
        if ip in login_attempts:
            del login_attempts[ip]
        add_login_log(ip, None, "unblocked", "관리자가 수동 해제")
        print(f"[차단 해제] {ip}")
        return True
    return False


def is_ip_blocked(ip):
    """IP 차단 여부 확인 (만료 시 자동 해제, 영구 차단은 제외)"""
    blocked_ips = load_blocked_ips()
    if ip not in blocked_ips:
        return False, None, False

    info = blocked_ips[ip]

    # 비활성 상태 (이전에 해제된 기록)인 경우 차단 아님
    is_active = info.get("active", True)
    if not is_active:
        return False, None, False

    is_permanent = info.get("permanent", False)
    expires_at_str = info.get("expires_at")

    # 영구 차단인 경우
    if is_permanent:
        return True, None, True

    # expires_at이 없는 비정상 기록은 무시
    if not expires_at_str:
        return False, None, False

    expires_at = datetime.fromisoformat(expires_at_str)
    if datetime.now() >= expires_at:
        # 만료됨 - 자동 해제 (차단 횟수는 유지)
        block_count = info.get("block_count", 1)
        # 차단 횟수 기록만 남기고 차단 해제
        blocked_ips[ip] = {
            "block_count": block_count,
            "last_unblocked": datetime.now().isoformat(),
            "permanent": False,
            "active": False  # 비활성 상태
        }
        save_blocked_ips(blocked_ips)
        if ip in login_attempts:
            del login_attempts[ip]
        add_login_log(ip, None, "expired", f"차단 시간 만료로 자동 해제 ({block_count}회 차단 기록)")
        print(f"[차단 해제] {ip} (만료, {block_count}회 차단 기록)")
        return False, None, False
    else:
        # 아직 차단 중
        return True, expires_at, False


def get_blocked_ips():
    """활성 차단된 IP 목록만 반환"""
    all_ips = load_blocked_ips()
    # active가 False가 아닌 것만 반환 (active 키가 없으면 활성으로 간주)
    return {ip: info for ip, info in all_ips.items() if info.get("active", True) != False}


# ============================================================
# 로그인 로그 관리
# ============================================================

def load_login_log():
    """로그인 로그 로드"""
    if os.path.exists(LOGIN_LOG_FILE):
        try:
            with open(LOGIN_LOG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return []


def save_login_log(logs):
    """로그인 로그 저장"""
    with open(LOGIN_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)


def add_login_log(ip, user_id, status, message=""):
    """로그인 로그 추가"""
    logs = load_login_log()
    logs.append({
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "user_id": user_id,
        "status": status,  # "success", "failed", "blocked"
        "message": message
    })
    # 최근 1000개만 유지
    if len(logs) > 1000:
        logs = logs[-1000:]
    save_login_log(logs)


def get_login_logs(limit=100):
    """최근 로그인 로그 반환"""
    logs = load_login_log()
    return logs[-limit:]


def get_ip_statistics():
    """IP별 통계 반환"""
    logs = load_login_log()
    blocked_ips = load_blocked_ips()
    stats = {}

    # 로그에서 IP별 통계 집계
    for log in logs:
        ip = log.get("ip", "")
        if not ip:
            continue

        if ip not in stats:
            stats[ip] = {"success": 0, "failed": 0, "blocked": 0, "last_access": ""}

        status = log.get("status", "")
        if status == "success":
            stats[ip]["success"] += 1
        elif status == "failed":
            stats[ip]["failed"] += 1
        elif status == "blocked":
            stats[ip]["blocked"] += 1

        stats[ip]["last_access"] = log.get("timestamp", "")

    # 차단 상태 추가
    for ip, info in blocked_ips.items():
        if ip not in stats:
            stats[ip] = {"success": 0, "failed": 0, "blocked": 0, "last_access": ""}

        is_active = info.get("active", True)
        is_permanent = info.get("permanent", False)
        block_count = info.get("block_count", 0)

        if is_active:
            stats[ip]["is_blocked"] = True
            stats[ip]["is_permanent"] = is_permanent
            stats[ip]["block_count"] = block_count
            stats[ip]["expires_at"] = info.get("expires_at")
        else:
            stats[ip]["is_blocked"] = False
            stats[ip]["block_count"] = block_count

    return stats


def manual_block_ip(ip, permanent=True):
    """수동으로 IP 차단"""
    blocked_ips = load_blocked_ips()
    blocked_at = datetime.now()

    # 기존 차단 횟수 유지
    block_count = 1
    if ip in blocked_ips:
        block_count = blocked_ips[ip].get("block_count", 0) + 1

    blocked_ips[ip] = {
        "blocked_at": blocked_at.isoformat(),
        "expires_at": None,
        "reason": "관리자 수동 차단",
        "block_count": block_count,
        "permanent": True,
        "active": True
    }
    save_blocked_ips(blocked_ips)
    add_login_log(ip, None, "blocked", "관리자 수동 차단 (영구)")
    print(f"[수동 차단] {ip} 영구 차단됨")


# ============================================================
# Brute Force 방어
# ============================================================

def check_login_attempt(ip):
    """
    로그인 시도 체크
    반환: (허용여부, 메시지)
    """
    # 이미 차단된 IP인지 확인
    blocked, expires_at, is_permanent = is_ip_blocked(ip)
    if blocked:
        if is_permanent:
            return False, "IP가 영구 차단되었습니다. 관리자에게 문의하세요."
        elif expires_at:
            expires_str = expires_at.strftime("%Y/%m/%d %H:%M:%S")
            return False, f"{expires_str}까지 차단되었습니다."
        else:
            return False, "IP가 차단되었습니다. 관리자에게 문의하세요."

    return True, ""


def record_failed_attempt(ip):
    """
    실패한 로그인 시도 기록
    반환: 차단 여부
    """
    current_time = time.time()
    max_attempts = config.get("max_login_attempts", 5)
    lockout_duration = config.get("lockout_duration", 300)

    if ip not in login_attempts:
        login_attempts[ip] = {"count": 1, "first_attempt": current_time}
    else:
        attempt_info = login_attempts[ip]
        # lockout_duration 이내의 시도인지 확인
        if current_time - attempt_info["first_attempt"] < lockout_duration:
            attempt_info["count"] += 1
        else:
            # 시간이 지났으면 초기화
            login_attempts[ip] = {"count": 1, "first_attempt": current_time}

    # 최대 시도 횟수 초과 시 차단
    if login_attempts[ip]["count"] >= max_attempts:
        block_ip(ip, f"{max_attempts}회 로그인 실패")
        del login_attempts[ip]
        return True

    return False


def clear_login_attempts(ip):
    """로그인 성공 시 시도 기록 초기화"""
    if ip in login_attempts:
        del login_attempts[ip]


def hash_password(password):
    """비밀번호 bcrypt 해시"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password, hashed):
    """비밀번호 검증"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


# 전역 설정
config = load_config()


# ============================================================
# Claude CLI 함수
# ============================================================

def get_claude_working_dir():
    """Claude 작업 디렉토리 반환"""
    work_dir = config.get("claude_working_dir", "")
    if work_dir and os.path.isdir(work_dir):
        return work_dir
    return WORKING_DIR


def get_relative_path(file_path: str) -> str:
    """절대 경로를 작업 디렉토리 기준 상대 경로로 변환"""
    if not file_path:
        return ""
    try:
        abs_path = os.path.abspath(file_path)
        work_dir = get_claude_working_dir()
        if abs_path.startswith(work_dir):
            rel_path = os.path.relpath(abs_path, work_dir)
            return rel_path.replace("\\", "/")
        return file_path
    except Exception:
        return file_path


def get_claude_usage():
    """ccusage를 통해 오늘의 Claude 사용량 조회"""
    try:
        result = subprocess.run(
            'npx ccusage@latest daily --json',
            capture_output=True,
            text=True,
            encoding="utf-8",
            shell=True,
            timeout=30
        )
        if result.returncode != 0:
            return None

        data = json.loads(result.stdout)
        daily_data = data.get("daily", [])
        totals = data.get("totals", {})

        today = datetime.now().strftime("%Y-%m-%d")
        today_usage = None
        for day in daily_data:
            if day.get("date") == today:
                today_usage = day
                break

        return {
            "today": today_usage,
            "totals": totals,
            "date": today
        }
    except Exception:
        return None


def get_claude_blocks():
    """ccusage를 통해 5시간 블록 사용량 조회"""
    try:
        result = subprocess.run(
            'npx ccusage@latest blocks --json',
            capture_output=True,
            text=True,
            encoding="utf-8",
            shell=True,
            timeout=30
        )
        if result.returncode != 0:
            return None

        data = json.loads(result.stdout)
        blocks = data.get("blocks", [])

        active_block = None
        for block in blocks:
            if block.get("isActive") and not block.get("isGap"):
                active_block = block
                break

        if not active_block:
            return None

        projection = active_block.get("projection", {})
        burn_rate = active_block.get("burnRate", {})

        return {
            "startTime": active_block.get("startTime"),
            "endTime": active_block.get("endTime"),
            "costUSD": active_block.get("costUSD", 0),
            "totalTokens": active_block.get("totalTokens", 0),
            "remainingMinutes": projection.get("remainingMinutes", 0) if projection else 0,
            "projectedCost": projection.get("totalCost", 0) if projection else 0,
            "costPerHour": burn_rate.get("costPerHour", 0) if burn_rate else 0,
            "models": active_block.get("models", [])
        }
    except Exception:
        return None


def run_claude_stream(prompt: str, output_queue: Queue, stop_event: threading.Event,
                      sess_id: str = None, is_resume: bool = False):
    """별도 스레드에서 Claude CLI 스트리밍 실행"""
    process = None
    try:
        cmd = 'claude --output-format stream-json --verbose'
        if config.get("claude_skip_permissions", True):
            cmd += ' --dangerously-skip-permissions'
        if sess_id:
            if is_resume:
                cmd += f' -r "{sess_id}"'
            else:
                cmd += f' --session-id "{sess_id}"'
        cmd += ' -p -'

        work_dir = get_claude_working_dir()

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            shell=True,
            text=True,
            encoding="utf-8",
            bufsize=1,
            cwd=work_dir
        )

        # stdin으로 프롬프트 전달
        process.stdin.write(prompt)
        process.stdin.close()

        # stderr 읽기 스레드
        def read_stderr():
            try:
                while not stop_event.is_set():
                    line = process.stderr.readline()
                    if not line:
                        break
                    line = line.strip()
                    if line:
                        output_queue.put(("stderr", line))
            except Exception:
                pass

        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()

        # stdout 읽기
        try:
            while not stop_event.is_set():
                line = process.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if line:
                    output_queue.put(("line", line))
        except Exception as e:
            output_queue.put(("error", f"stdout 읽기 오류: {e}"))

        # 프로세스 종료 대기
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

        output_queue.put(("done", process.returncode))

    except Exception as e:
        output_queue.put(("error", str(e)))
    finally:
        if process and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=5)
            except:
                pass


def reset_claude_session():
    """Claude 세션 리셋"""
    global claude_session_id, claude_session_started
    claude_session_id = str(uuid.uuid4())
    claude_session_started = False
    print(f"[Claude 세션] 리셋됨: {claude_session_id[:8]}...")
    return claude_session_id


# ============================================================
# Claude 브로드캐스트 함수 (인증된 클라이언트 전용)
# ============================================================

async def broadcast_to_authenticated(message: dict, exclude_token=None):
    """인증된 모든 클라이언트에게 메시지 전송"""
    if not token_connections:
        return

    message_str = json.dumps(message, ensure_ascii=False)
    disconnected = []

    for token, ws in token_connections.items():
        if token != exclude_token:
            try:
                if not ws.closed:
                    await ws.send_str(message_str)
            except Exception:
                disconnected.append(token)

    for token in disconnected:
        token_connections.pop(token, None)


async def send_progress(progress_type: str, data: dict):
    """진행 상황 브로드캐스트"""
    await broadcast_to_authenticated({
        "type": "progress",
        "progress_type": progress_type,
        **data
    })


async def send_queue_status(ws=None):
    """현재 큐 상태를 클라이언트에게 전송 (ws가 없으면 브로드캐스트)"""
    items = []
    for req in request_queue:
        items.append({
            "sender": req["sender"],
            "message": req["message"][:50] + ("..." if len(req["message"]) > 50 else "")
        })

    data = {
        "type": "queue_status",
        "count": len(request_queue),
        "items": items
    }

    if ws:
        # 개별 클라이언트에게 전송
        try:
            if not ws.closed:
                await ws.send_str(json.dumps(data))
        except Exception as e:
            print(f"[경고] 큐 상태 전송 실패: {e}")
    else:
        # 모든 클라이언트에게 브로드캐스트
        await broadcast_to_authenticated(data)


async def send_usage_status(ws=None):
    """Claude 사용량 상태를 클라이언트에게 전송 (ws가 없으면 브로드캐스트)"""
    try:
        loop = asyncio.get_event_loop()
        usage_task = loop.run_in_executor(None, get_claude_usage)
        blocks_task = loop.run_in_executor(None, get_claude_blocks)

        usage = await usage_task
        blocks = await blocks_task

        combined_data = {}
        if usage:
            combined_data["today"] = usage.get("today")
            combined_data["totals"] = usage.get("totals")
            combined_data["date"] = usage.get("date")

        if blocks:
            combined_data["block"] = blocks

        if combined_data:
            data = {
                "type": "usage_status",
                **combined_data
            }

            if ws:
                # 개별 클라이언트에게 전송
                try:
                    if not ws.closed:
                        await ws.send_str(json.dumps(data))
                except Exception as e:
                    print(f"[경고] 사용량 상태 전송 실패: {e}")
            else:
                # 모든 클라이언트에게 브로드캐스트
                await broadcast_to_authenticated(data)
    except Exception as e:
        print(f"[경고] 사용량 상태 조회 실패: {e}")


async def add_to_queue(message: str, sender: str):
    """요청을 큐에 추가"""
    async with queue_lock:
        request_queue.append({
            "sender": sender,
            "message": message
        })
        print(f"[큐] 요청 추가: {sender} (대기: {len(request_queue)}개)")
        await send_queue_status()

    # 처리 시작 (처리 중이 아닐 때만)
    if not claude_processing:
        asyncio.create_task(process_queue())


async def process_queue():
    """큐에서 요청을 꺼내 순차 처리"""
    global claude_processing

    while True:
        async with queue_lock:
            if not request_queue:
                print("[큐] 모든 요청 처리 완료")
                return
            request = request_queue[0]

        await ask_claude(request["message"], request["sender"])

        async with queue_lock:
            if request_queue and request_queue[0] == request:
                request_queue.popleft()
                print(f"[큐] 요청 완료 (남은: {len(request_queue)}개)")
            await send_queue_status()
            await send_usage_status()


async def ask_claude(message: str, sender: str, retry_count: int = 0):
    """Claude CLI에 메시지 전달하고 응답 받기"""
    global claude_processing, current_stop_event, claude_session_id, claude_session_started

    MAX_RETRY = 1
    CLAUDE_TIMEOUT = config.get("claude_timeout", 300)

    # 세션 ID가 없으면 새로 생성
    if claude_session_id is None:
        claude_session_id = str(uuid.uuid4())
        claude_session_started = False

    claude_processing = True
    current_stop_event = threading.Event()

    try:
        await send_progress("start", {"message": "Claude 처리 시작"})
        print(f"[Claude] 처리 시작: {sender} - {message[:50]}...")

        prompt = f"[{sender}]: {message}"
        output_queue = Queue()

        thread = threading.Thread(
            target=run_claude_stream,
            args=(prompt, output_queue, current_stop_event, claude_session_id, claude_session_started)
        )
        thread.start()

        final_result = ""
        current_turn = 0
        start_time = asyncio.get_event_loop().time()
        session_error_detected = False

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > CLAUDE_TIMEOUT:
                print(f"[Claude] 타임아웃 ({CLAUDE_TIMEOUT}초)")
                current_stop_event.set()
                await send_progress("error", {"message": f"타임아웃 ({CLAUDE_TIMEOUT}초)"})
                reset_claude_session()
                break

            try:
                item = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, lambda: output_queue.get(timeout=1)
                    ),
                    timeout=2
                )
            except (asyncio.TimeoutError, Empty):
                continue

            msg_type, content = item

            if msg_type == "done":
                if session_error_detected and retry_count < MAX_RETRY:
                    print(f"[Claude] 세션 에러로 인한 재시도 ({retry_count + 1}/{MAX_RETRY})")
                    thread.join(timeout=5)
                    reset_claude_session()
                    claude_processing = False
                    await send_progress("retry", {"message": "세션 에러 - 새 세션으로 재시도 중..."})
                    return await ask_claude(message, sender, retry_count + 1)
                break
            elif msg_type == "error":
                print(f"[Claude 오류]: {content}")
                await send_progress("error", {"message": content})
                break
            elif msg_type == "stderr":
                content_lower = content.lower()
                if "state" in content_lower or "session" in content_lower or "invalid" in content_lower:
                    print(f"[Claude] 세션 에러 감지: {content}")
                    session_error_detected = True
            elif msg_type == "line":
                try:
                    data = json.loads(content)
                    json_type = data.get("type", "")

                    if json_type == "system" and data.get("subtype") == "init":
                        model = data.get("model", "unknown")
                        print(f"[Claude] 모델: {model}")
                        await send_progress("init", {
                            "model": model,
                            "session_id": data.get("session_id", "")
                        })

                    elif json_type == "assistant":
                        msg = data.get("message", {})
                        if isinstance(msg, dict):
                            msg_content = msg.get("content", [])
                            if isinstance(msg_content, list):
                                for content_item in msg_content:
                                    if not isinstance(content_item, dict):
                                        continue

                                    if content_item.get("type") == "tool_use":
                                        tool_name = content_item.get("name", "unknown")
                                        tool_input = content_item.get("input", {})
                                        if not isinstance(tool_input, dict):
                                            tool_input = {}
                                        current_turn += 1

                                        detail = ""
                                        edit_info = None

                                        if tool_name == "Read":
                                            file_path = tool_input.get("file_path", "")
                                            detail = get_relative_path(file_path) if file_path else ""
                                        elif tool_name == "Bash":
                                            cmd = tool_input.get("command", "")
                                            detail = cmd[:100] if cmd else ""
                                        elif tool_name == "Edit":
                                            file_path = tool_input.get("file_path", "")
                                            rel_path = get_relative_path(file_path)
                                            detail = rel_path if file_path else ""
                                            old_string = tool_input.get("old_string", "")
                                            new_string = tool_input.get("new_string", "")
                                            if old_string or new_string:
                                                edit_info = {
                                                    "type": "edit",
                                                    "file": rel_path,
                                                    "old": old_string[:500] if old_string else "",
                                                    "new": new_string[:500] if new_string else ""
                                                }
                                        elif tool_name == "Write":
                                            file_path = tool_input.get("file_path", "")
                                            rel_path = get_relative_path(file_path)
                                            detail = rel_path if file_path else ""
                                            write_content = tool_input.get("content", "")
                                            if write_content:
                                                edit_info = {
                                                    "type": "write",
                                                    "file": rel_path,
                                                    "content": write_content[:500] if write_content else ""
                                                }
                                        elif tool_name == "Grep":
                                            detail = tool_input.get("pattern", "") or ""

                                        print(f"[Claude] [{current_turn}] {tool_name} {detail}")
                                        progress_data = {
                                            "turn": current_turn,
                                            "tool": tool_name,
                                            "detail": detail
                                        }
                                        if edit_info:
                                            progress_data["edit_info"] = edit_info
                                        await send_progress("tool_start", progress_data)

                                    elif content_item.get("type") == "text":
                                        final_result = content_item.get("text", "")

                    elif json_type == "user":
                        tool_result = data.get("tool_use_result", {})
                        if tool_result and isinstance(tool_result, dict):
                            file_info = tool_result.get("file", {})
                            if file_info and isinstance(file_info, dict):
                                lines = file_info.get("numLines", 0)
                                await send_progress("tool_end", {
                                    "turn": current_turn,
                                    "lines": lines
                                })
                            else:
                                await send_progress("tool_end", {"turn": current_turn})

                    elif json_type == "result":
                        total_turns = data.get("num_turns", 0)
                        duration_ms = data.get("duration_ms", 0)
                        cost_usd = data.get("total_cost_usd", 0)
                        usage = data.get("usage", {})
                        if not isinstance(usage, dict):
                            usage = {}

                        duration_sec = duration_ms / 1000
                        input_tokens = usage.get("input_tokens", 0)
                        output_tokens = usage.get("output_tokens", 0)
                        cache_tokens = usage.get("cache_read_input_tokens", 0)

                        final_result = data.get("result", final_result)

                        cost_krw = cost_usd * USD_TO_KRW
                        print(f"[Claude] 완료 | {duration_sec:.1f}초 | ${cost_usd:.4f} (₩{cost_krw:.0f})")
                        await send_progress("complete", {
                            "duration_sec": duration_sec,
                            "cost_usd": cost_usd,
                            "cost_krw": cost_krw,
                            "input_tokens": input_tokens + cache_tokens,
                            "output_tokens": output_tokens,
                            "turns": total_turns
                        })

                except json.JSONDecodeError:
                    continue

        thread.join(timeout=10)

        if final_result:
            print(f"[Claude]: {final_result[:100]}...")
            await broadcast_to_authenticated({
                "type": "message",
                "username": "Claude",
                "message": final_result
            })
            if not claude_session_started:
                claude_session_started = True
                print(f"[Claude] 세션 시작됨: {claude_session_id[:8]}...")

    except Exception as e:
        print(f"[Claude 오류]: {type(e).__name__}: {e}")
        await send_progress("error", {"message": str(e)})
    finally:
        claude_processing = False


# ============================================================
# HTTP 핸들러
# ============================================================

async def handle_index(request):
    """HTTP GET / - index.html 제공"""
    index_path = os.path.join(SCRIPT_DIR, "index.html")
    if os.path.exists(index_path):
        return web.FileResponse(index_path)
    return web.Response(text="index.html not found", status=404)


async def handle_manifest(request):
    """HTTP GET /manifest.json - PWA 매니페스트 제공"""
    manifest_path = os.path.join(SCRIPT_DIR, "manifest.json")
    if os.path.exists(manifest_path):
        return web.FileResponse(manifest_path, headers={"Content-Type": "application/manifest+json"})
    return web.Response(text="manifest.json not found", status=404)


async def handle_service_worker(request):
    """HTTP GET /service-worker.js - 서비스 워커 제공"""
    sw_path = os.path.join(SCRIPT_DIR, "service-worker.js")
    if os.path.exists(sw_path):
        return web.FileResponse(sw_path, headers={"Content-Type": "application/javascript"})
    return web.Response(text="service-worker.js not found", status=404)


async def handle_icon(request):
    """HTTP GET /icons/{filename} - PWA 아이콘 제공"""
    filename = request.match_info.get("filename", "")
    # 보안: 경로 탐색 공격 방지
    if ".." in filename or "/" in filename or "\\" in filename:
        return web.Response(text="Invalid filename", status=400)

    icon_path = os.path.join(SCRIPT_DIR, "icons", filename)
    if os.path.exists(icon_path):
        content_type = "image/png"
        if filename.endswith(".svg"):
            content_type = "image/svg+xml"
        return web.FileResponse(icon_path, headers={"Content-Type": content_type})
    return web.Response(text="Icon not found", status=404)


async def handle_login(request):
    """HTTP POST /login - 로그인 처리"""
    # 클라이언트 IP 가져오기
    peername = request.transport.get_extra_info('peername')
    client_ip = peername[0] if peername else "unknown"

    # X-Forwarded-For 헤더 확인 (프록시/ngrok 사용 시)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        client_ip = forwarded_for.split(',')[0].strip()

    try:
        # IP 차단 여부 확인
        allowed, block_message = check_login_attempt(client_ip)
        if not allowed:
            add_login_log(client_ip, None, "blocked", block_message)
            return web.json_response({"success": False, "message": block_message}, status=429)

        data = await request.json()
        user_id = data.get("id", "").strip()
        password = data.get("password", "")

        if not user_id or not password:
            return web.json_response({"success": False, "message": "아이디와 비밀번호를 입력하세요."}, status=400)

        # 계정 확인
        for account in config.get("accounts", []):
            if account["id"] == user_id:
                if verify_password(password, account["password"]):
                    # 토큰 생성 (만료 시간 포함)
                    token = secrets.token_urlsafe(32)
                    session_timeout = config.get("session_timeout", 3600)
                    current_time = time.time()
                    sessions[token] = {
                        "id": user_id,
                        "created_at": current_time,
                        "expires_at": current_time + session_timeout
                    }
                    clear_login_attempts(client_ip)
                    add_login_log(client_ip, user_id, "success")
                    print(f"[로그인] {user_id} 로그인 성공 (IP: {client_ip})")
                    return web.json_response({"success": True, "token": token, "id": user_id})
                else:
                    # 로그인 실패 - 비밀번호 오류
                    blocked = record_failed_attempt(client_ip)
                    remaining = config.get("max_login_attempts", 5) - login_attempts.get(client_ip, {}).get("count", 0)
                    add_login_log(client_ip, user_id, "failed", "비밀번호 오류")
                    print(f"[로그인] {user_id} 비밀번호 오류 (IP: {client_ip})")
                    if blocked:
                        return web.json_response({"success": False, "message": "로그인 시도 횟수 초과로 IP가 차단되었습니다."}, status=429)
                    return web.json_response({"success": False, "message": f"아이디 또는 비밀번호가 올바르지 않습니다. (남은 시도: {remaining}회)"}, status=401)

        # 로그인 실패 - 계정 없음 (동일한 메시지로 응답)
        blocked = record_failed_attempt(client_ip)
        remaining = config.get("max_login_attempts", 5) - login_attempts.get(client_ip, {}).get("count", 0)
        add_login_log(client_ip, user_id, "failed", "계정 없음")
        print(f"[로그인] {user_id} 계정 없음 (IP: {client_ip})")
        if blocked:
            return web.json_response({"success": False, "message": "로그인 시도 횟수 초과로 IP가 차단되었습니다."}, status=429)
        return web.json_response({"success": False, "message": f"아이디 또는 비밀번호가 올바르지 않습니다. (남은 시도: {remaining}회)"}, status=401)

    except Exception as e:
        print(f"[오류] 로그인 처리 중 오류: {e}")
        return web.json_response({"success": False, "message": "서버 오류"}, status=500)


async def handle_logout(request):
    """HTTP POST /logout - 로그아웃 처리"""
    try:
        data = await request.json()
        token = data.get("token", "")

        if not token:
            return web.json_response({"success": False, "message": "토큰이 필요합니다."}, status=400)

        if token not in sessions:
            # 이미 만료되었거나 없는 토큰
            return web.json_response({"success": True, "message": "로그아웃 완료"})

        user_id = sessions[token].get("id", "unknown")

        # 해당 토큰의 WebSocket 연결 종료
        if token in token_connections:
            ws = token_connections[token]
            if not ws.closed:
                await ws.close(code=4002, message=b"Logged out")
            del token_connections[token]

        # 세션 삭제
        del sessions[token]

        print(f"[로그아웃] {user_id} 로그아웃")
        return web.json_response({"success": True, "message": "로그아웃 완료"})

    except Exception as e:
        print(f"[오류] 로그아웃 처리 중 오류: {e}")
        return web.json_response({"success": False, "message": "서버 오류"}, status=500)


# ============================================================
# WebSocket 핸들러
# ============================================================

async def handle_websocket(request):
    """WebSocket /ws - 채팅 처리 (토큰은 첫 메시지로 전송)"""
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)

    token = None
    user_id = None
    authenticated = False

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                # 인증 전: 첫 메시지로 토큰 검증
                if not authenticated:
                    try:
                        auth_data = json.loads(msg.data)
                        if auth_data.get("type") == "auth":
                            token = auth_data.get("token")

                            # 토큰 검증
                            if not token or token not in sessions:
                                await ws.send_str(json.dumps({"type": "auth", "success": False, "message": "Invalid token"}))
                                await ws.close(code=4001, message=b"Invalid token")
                                return ws

                            user_info = sessions[token]
                            user_id = user_info["id"]

                            # 세션 만료 확인
                            if time.time() > user_info.get("expires_at", float('inf')):
                                del sessions[token]
                                print(f"[세션 만료] {user_id} 세션이 만료되었습니다.")
                                await ws.send_str(json.dumps({"type": "auth", "success": False, "message": "Session expired"}))
                                await ws.close(code=4002, message=b"Session expired")
                                return ws

                            # 동일 토큰으로 기존 연결이 있으면 종료 (중복 연결 방지)
                            if token in token_connections:
                                old_ws = token_connections[token]
                                if not old_ws.closed:
                                    print(f"[중복 연결] {user_id} 기존 연결 종료")
                                    await old_ws.close(code=4003, message=b"New connection established")

                            # 연결 등록 및 인증 완료
                            token_connections[token] = ws
                            authenticated = True
                            print(f"[연결] {user_id} WebSocket 접속 (토큰 인증 완료)")
                            await ws.send_str(json.dumps({"type": "auth", "success": True}))
                        else:
                            await ws.send_str(json.dumps({"type": "error", "message": "Authentication required"}))
                    except json.JSONDecodeError:
                        await ws.send_str(json.dumps({"type": "error", "message": "Invalid JSON"}))
                else:
                    # 인증 후: 메시지 타입별 처리
                    try:
                        data = json.loads(msg.data)
                        msg_type = data.get("type", "")

                        if msg_type == "chat":
                            # 채팅 메시지 처리 - Claude CLI로 전송
                            message = data.get("message", "").strip()
                            if message:
                                print(f"[채팅] {user_id}: {message}")
                                # 큐에 추가하고 처리
                                await add_to_queue(message, user_id)
                            else:
                                await ws.send_str(json.dumps({
                                    "type": "error",
                                    "message": "빈 메시지는 전송할 수 없습니다."
                                }))

                        elif msg_type == "usage":
                            # 사용량 조회 요청
                            print(f"[사용량 조회] {user_id}")
                            asyncio.create_task(send_usage_status(ws))

                        elif msg_type == "reset":
                            # Claude 세션 리셋 요청
                            print(f"[세션 리셋] {user_id}")
                            reset_claude_session()
                            await ws.send_str(json.dumps({
                                "type": "system",
                                "message": "Claude 세션이 리셋되었습니다."
                            }))
                            # 모든 클라이언트에 알림
                            await broadcast_to_authenticated({
                                "type": "system",
                                "message": f"{user_id}님이 Claude 세션을 리셋했습니다."
                            })

                        elif msg_type == "queue_status":
                            # 큐 상태 조회
                            print(f"[큐 상태 조회] {user_id}")
                            await send_queue_status(ws)

                        else:
                            # 알 수 없는 메시지 타입
                            print(f"[알 수 없는 타입] {user_id}: {msg_type}")
                            await ws.send_str(json.dumps({
                                "type": "error",
                                "message": f"알 수 없는 메시지 타입: {msg_type}"
                            }))

                    except json.JSONDecodeError:
                        # JSON이 아닌 경우 일반 텍스트로 처리 (chat으로 간주)
                        message = msg.data.strip()
                        if message:
                            print(f"[채팅] {user_id}: {message}")
                            await add_to_queue(message, user_id)

            elif msg.type == web.WSMsgType.ERROR:
                print(f"[오류] WebSocket 오류: {ws.exception()}")
    except Exception as e:
        print(f"[오류] {e}")
    finally:
        # 연결 해제 시 등록 삭제
        if token and token in token_connections and token_connections[token] is ws:
            del token_connections[token]
        if user_id:
            print(f"[연결 해제] {user_id} WebSocket 종료")

    return ws


# ============================================================
# CORS 미들웨어
# ============================================================

def get_allowed_origins():
    """허용된 Origin 목록 반환"""
    host = config.get("host", "0.0.0.0")
    port = config.get("port", 8765)

    origins = [
        f"http://localhost:{port}",
        f"http://127.0.0.1:{port}",
    ]

    # 0.0.0.0으로 바인딩된 경우 로컬 IP도 허용
    if host == "0.0.0.0":
        try:
            import socket
            local_ip = socket.gethostbyname(socket.gethostname())
            origins.append(f"http://{local_ip}:{port}")
        except:
            pass

    # ngrok 도메인 허용 (HTTPS)
    # ngrok URL은 동적이므로 *.ngrok.io, *.ngrok-free.app 패턴 허용
    return origins


def is_origin_allowed(origin):
    """Origin 허용 여부 확인"""
    if not origin:
        return True  # Same-origin 요청

    # ngrok 도메인 허용
    if ".ngrok.io" in origin or ".ngrok-free.app" in origin or ".ngrok.app" in origin or ".ngrok.dev" in origin:
        return True

    # 허용된 origin 목록 확인
    allowed = get_allowed_origins()
    return origin in allowed


@web.middleware
async def cors_middleware(request, handler):
    """CORS 미들웨어"""
    origin = request.headers.get("Origin", "")

    # Origin 검증
    if not is_origin_allowed(origin):
        return web.Response(text="CORS policy: Origin not allowed", status=403)

    # Preflight 요청 (OPTIONS) 처리
    if request.method == "OPTIONS":
        response = web.Response(status=204)
    else:
        response = await handler(request)

    # CORS 헤더 추가
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Max-Age"] = "86400"  # 24시간 캐시

    return response


# ============================================================
# 앱 초기화
# ============================================================

async def init_app():
    """aiohttp 앱 초기화"""
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get("/", handle_index)
    app.router.add_post("/login", handle_login)
    app.router.add_post("/logout", handle_logout)
    app.router.add_get("/ws", handle_websocket)
    # PWA 관련 엔드포인트
    app.router.add_get("/manifest.json", handle_manifest)
    app.router.add_get("/service-worker.js", handle_service_worker)
    app.router.add_get("/icons/{filename}", handle_icon)
    return app


# ============================================================
# 서버 실행 (별도 스레드)
# ============================================================

class ServerThread(threading.Thread):
    def __init__(self, host, port):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.loop = None
        self.runner = None

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.start_server())
        self.loop.run_forever()

    async def start_server(self):
        app = await init_app()
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()
        print(f"[서버] http://{self.host}:{self.port}/ 에서 실행 중")

    async def _cleanup(self):
        """서버 리소스 정리"""
        if self.runner:
            await self.runner.cleanup()
            print("[서버] 종료됨")

    def stop(self):
        """서버 중지"""
        if self.loop and self.runner:
            # cleanup 코루틴을 실행하고 완료 대기
            future = asyncio.run_coroutine_threadsafe(self._cleanup(), self.loop)
            try:
                future.result(timeout=5)  # 5초 타임아웃
            except Exception as e:
                print(f"[오류] 서버 종료 중 오류: {e}")
            finally:
                self.loop.call_soon_threadsafe(self.loop.stop)


# ============================================================
# 계정 추가 다이얼로그
# ============================================================

class AddAccountDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("계정 추가")
        self.geometry("300x250")
        self.resizable(False, False)
        self.result = None

        # 다크 테마
        self.configure(bg="#1a1a2e")

        # 모달 설정
        self.transient(parent)
        self.grab_set()

        self.create_widgets()
        self.center_window(parent)

    def center_window(self, parent):
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    def create_widgets(self):
        bg = "#1a1a2e"
        fg = "#eeeeee"
        warning_color = "#fbbf24"

        frame = tk.Frame(self, bg=bg, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # 경고 문구
        warning_frame = tk.Frame(frame, bg="#3a2a1a", padx=8, pady=8)
        warning_frame.grid(row=0, column=0, columnspan=2, sticky=tk.EW, pady=(0, 15))
        tk.Label(warning_frame, text="⚠ 계정 정보가 고수준으로 보호되지 않습니다.\n이 소프트웨어 전용 아이디와 패스워드를\n별도로 지정하세요.",
                 bg="#3a2a1a", fg=warning_color, font=("Segoe UI", 8), justify=tk.LEFT).pack()

        # 아이디
        tk.Label(frame, text="아이디:", bg=bg, fg=fg).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.id_entry = tk.Entry(frame, width=25)
        self.id_entry.grid(row=1, column=1, pady=5)

        # 비밀번호
        tk.Label(frame, text="비밀번호:", bg=bg, fg=fg).grid(row=2, column=0, sticky=tk.W, pady=5)
        self.pw_entry = tk.Entry(frame, width=25, show="*")
        self.pw_entry.grid(row=2, column=1, pady=5)

        # 비밀번호 확인
        tk.Label(frame, text="비밀번호 확인:", bg=bg, fg=fg).grid(row=3, column=0, sticky=tk.W, pady=5)
        self.pw_confirm_entry = tk.Entry(frame, width=25, show="*")
        self.pw_confirm_entry.grid(row=3, column=1, pady=5)

        # 버튼
        btn_frame = tk.Frame(frame, bg=bg)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(15, 0))

        tk.Button(btn_frame, text="취소", command=self.cancel, width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="추가", command=self.submit, width=10).pack(side=tk.LEFT, padx=5)

        self.id_entry.focus_set()

    def submit(self):
        user_id = self.id_entry.get().strip()
        password = self.pw_entry.get()
        password_confirm = self.pw_confirm_entry.get()

        if not user_id:
            messagebox.showerror("오류", "아이디를 입력하세요.", parent=self)
            return

        if not password:
            messagebox.showerror("오류", "비밀번호를 입력하세요.", parent=self)
            return

        if password != password_confirm:
            messagebox.showerror("오류", "비밀번호가 일치하지 않습니다.", parent=self)
            return

        self.result = {"id": user_id, "password": password}
        self.destroy()

    def cancel(self):
        self.destroy()


# ============================================================
# 로그 뷰어 다이얼로그
# ============================================================

class LogViewerDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("로그인 로그")
        self.geometry("600x400")
        self.resizable(True, True)

        # 다크 테마
        self.configure(bg="#1a1a2e")

        # 모달 설정
        self.transient(parent)

        self.create_widgets()
        self.center_window(parent)
        self.load_logs()

    def center_window(self, parent):
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    def create_widgets(self):
        bg = "#1a1a2e"
        fg = "#eeeeee"

        # 메인 프레임
        frame = tk.Frame(self, bg=bg, padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # 로그 텍스트
        text_frame = tk.Frame(frame, bg=bg)
        text_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text = tk.Text(text_frame, bg="#0a0a0a", fg=fg,
                                yscrollcommand=scrollbar.set,
                                font=("Consolas", 9), wrap=tk.NONE)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.log_text.yview)

        # 태그 설정 (상태별 색상)
        self.log_text.tag_configure("success", foreground="#4ade80")
        self.log_text.tag_configure("failed", foreground="#fbbf24")
        self.log_text.tag_configure("blocked", foreground="#ef4444")
        self.log_text.tag_configure("unblocked", foreground="#60a5fa")
        self.log_text.tag_configure("expired", foreground="#a78bfa")

        # 버튼 프레임
        btn_frame = tk.Frame(frame, bg=bg)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        refresh_btn = tk.Button(btn_frame, text="새로고침", command=self.load_logs,
                               bg="#6366f1", fg="white")
        refresh_btn.pack(side=tk.LEFT, padx=(0, 5))

        clear_btn = tk.Button(btn_frame, text="로그 삭제", command=self.clear_logs,
                             bg="#ef4444", fg="white")
        clear_btn.pack(side=tk.LEFT)

        close_btn = tk.Button(btn_frame, text="닫기", command=self.destroy,
                             bg="#666", fg="white")
        close_btn.pack(side=tk.RIGHT)

    def load_logs(self):
        """로그 로드"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)

        # 상태 한글 변환
        status_labels = {
            "success": "성공",
            "failed": "실패",
            "blocked": "차단",
            "unblocked": "해제",
            "expired": "만료"
        }

        logs = get_login_logs(100)
        for log in reversed(logs):
            timestamp = log.get("timestamp", "")[:19].replace("T", " ")
            ip = log.get("ip", "")
            user_id = log.get("user_id") or "-"
            status = log.get("status", "")
            status_label = status_labels.get(status, status)
            message = log.get("message", "")

            line = f"[{timestamp}] {ip:15} {user_id:10} [{status_label:4}]"
            if message:
                line += f" {message}"
            line += "\n"

            self.log_text.insert(tk.END, line, status)

        if not logs:
            self.log_text.insert(tk.END, "로그가 없습니다.\n")

        self.log_text.config(state=tk.DISABLED)

    def clear_logs(self):
        """로그 삭제"""
        if messagebox.askyesno("확인", "모든 로그인 로그를 삭제하시겠습니까?", parent=self):
            save_login_log([])
            self.load_logs()
            messagebox.showinfo("완료", "로그가 삭제되었습니다.", parent=self)


# ============================================================
# GUI (tkinter)
# ============================================================

class ConfigGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Claude Portable")
        self.root.resizable(False, False)
        self.root.minsize(400, 0)  # 최소 너비만 설정

        # 다크 테마 색상
        self.bg_color = "#1a1a2e"
        self.fg_color = "#eeeeee"
        self.accent_color = "#6366f1"

        self.root.configure(bg=self.bg_color)

        self.server_thread = None
        self.log_viewer_dialog = None
        self.create_widgets()
        self.load_config_to_gui()

    def create_widgets(self):
        # 스타일 설정
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", background=self.bg_color, foreground=self.fg_color)
        style.configure("TFrame", background=self.bg_color)
        style.configure("TButton", padding=6)
        style.configure("TCheckbutton", background=self.bg_color, foreground=self.fg_color)
        style.configure("TLabelframe", background=self.bg_color, foreground=self.fg_color)
        style.configure("TLabelframe.Label", background=self.bg_color, foreground=self.fg_color)

        # 메인 프레임
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 제목
        title_label = tk.Label(main_frame, text="Claude Portable",
                               font=("Segoe UI", 16, "bold"),
                               bg=self.bg_color, fg=self.accent_color)
        title_label.pack(pady=(0, 15))

        # 서버 설정 프레임
        server_frame = ttk.LabelFrame(main_frame, text="서버 설정", padding=10)
        server_frame.pack(fill=tk.X, pady=(0, 10))

        # 포트
        port_frame = ttk.Frame(server_frame)
        port_frame.pack(fill=tk.X, pady=2)
        ttk.Label(port_frame, text="포트:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value=str(config["port"]))
        self.port_entry = ttk.Entry(port_frame, textvariable=self.port_var, width=10)
        self.port_entry.pack(side=tk.RIGHT)

        # 타임아웃
        timeout_frame = ttk.Frame(server_frame)
        timeout_frame.pack(fill=tk.X, pady=2)
        ttk.Label(timeout_frame, text="타임아웃 (초):").pack(side=tk.LEFT)
        self.timeout_var = tk.StringVar(value=str(config["timeout"]))
        self.timeout_entry = ttk.Entry(timeout_frame, textvariable=self.timeout_var, width=10)
        self.timeout_entry.pack(side=tk.RIGHT)

        # 계정 설정 프레임
        account_frame = ttk.LabelFrame(main_frame, text="계정 설정", padding=10)
        account_frame.pack(fill=tk.X, pady=(0, 10))

        # 계정 목록 헤더
        account_header = ttk.Frame(account_frame)
        account_header.pack(fill=tk.X)
        ttk.Label(account_header, text="등록된 계정:").pack(side=tk.LEFT)
        add_btn = tk.Button(account_header, text="+", command=self.add_account,
                           width=3, bg="#4ade80", fg="white", font=("Segoe UI", 10, "bold"))
        add_btn.pack(side=tk.RIGHT)

        # 계정 목록
        self.account_listbox = tk.Listbox(account_frame, height=4, bg="#0a0a0a", fg=self.fg_color,
                                          selectbackground=self.accent_color, selectforeground="white",
                                          borderwidth=1, relief=tk.SOLID)
        self.account_listbox.pack(fill=tk.X, pady=(5, 5))

        # 계정 삭제 버튼
        delete_btn = tk.Button(account_frame, text="선택 삭제", command=self.delete_account,
                              bg="#ef4444", fg="white")
        delete_btn.pack(anchor=tk.E)

        # 보안 설정 프레임
        security_frame = ttk.LabelFrame(main_frame, text="보안 설정", padding=10)
        security_frame.pack(fill=tk.X, pady=(0, 10))

        # 최대 로그인 시도
        max_attempts_frame = ttk.Frame(security_frame)
        max_attempts_frame.pack(fill=tk.X, pady=2)
        ttk.Label(max_attempts_frame, text="최대 로그인 시도:").pack(side=tk.LEFT)
        self.max_attempts_var = tk.StringVar(value=str(config.get("max_login_attempts", 5)))
        ttk.Entry(max_attempts_frame, textvariable=self.max_attempts_var, width=10).pack(side=tk.RIGHT)

        # 차단 시간
        lockout_frame = ttk.Frame(security_frame)
        lockout_frame.pack(fill=tk.X, pady=2)
        ttk.Label(lockout_frame, text="차단 시간 (초):").pack(side=tk.LEFT)
        self.lockout_var = tk.StringVar(value=str(config.get("lockout_duration", 300)))
        ttk.Entry(lockout_frame, textvariable=self.lockout_var, width=10).pack(side=tk.RIGHT)

        # 최대 자동 해제 횟수
        max_unblock_frame = ttk.Frame(security_frame)
        max_unblock_frame.pack(fill=tk.X, pady=2)
        ttk.Label(max_unblock_frame, text="최대 자동 해제 횟수:").pack(side=tk.LEFT)
        self.max_unblock_var = tk.StringVar(value=str(config.get("max_auto_unblock", 3)))
        ttk.Entry(max_unblock_frame, textvariable=self.max_unblock_var, width=10).pack(side=tk.RIGHT)

        # 세션 만료 시간
        session_frame = ttk.Frame(security_frame)
        session_frame.pack(fill=tk.X, pady=2)
        ttk.Label(session_frame, text="세션 만료 시간 (초):").pack(side=tk.LEFT)
        self.session_timeout_var = tk.StringVar(value=str(config.get("session_timeout", 3600)))
        ttk.Entry(session_frame, textvariable=self.session_timeout_var, width=10).pack(side=tk.RIGHT)

        # Claude CLI 설정 프레임
        claude_frame = ttk.LabelFrame(main_frame, text="Claude CLI 설정", padding=10)
        claude_frame.pack(fill=tk.X, pady=(0, 10))

        # Claude 타임아웃
        claude_timeout_frame = ttk.Frame(claude_frame)
        claude_timeout_frame.pack(fill=tk.X, pady=2)
        ttk.Label(claude_timeout_frame, text="응답 타임아웃 (초):").pack(side=tk.LEFT)
        self.claude_timeout_var = tk.StringVar(value=str(config.get("claude_timeout", 300)))
        ttk.Entry(claude_timeout_frame, textvariable=self.claude_timeout_var, width=10).pack(side=tk.RIGHT)

        # 작업 디렉토리
        workdir_frame = ttk.Frame(claude_frame)
        workdir_frame.pack(fill=tk.X, pady=2)
        ttk.Label(workdir_frame, text="작업 디렉토리:").pack(side=tk.LEFT)
        self.claude_workdir_var = tk.StringVar(value=config.get("claude_working_dir", ""))
        workdir_entry = ttk.Entry(workdir_frame, textvariable=self.claude_workdir_var, width=20)
        workdir_entry.pack(side=tk.LEFT, padx=(5, 5), fill=tk.X, expand=True)
        browse_btn = tk.Button(workdir_frame, text="찾기", command=self.browse_working_dir,
                              bg="#6366f1", fg="white", width=5)
        browse_btn.pack(side=tk.RIGHT)

        # 권한 스킵 옵션
        self.claude_skip_permissions_var = tk.BooleanVar(value=config.get("claude_skip_permissions", True))
        skip_perm_check = ttk.Checkbutton(claude_frame, text="권한 확인 스킵 (--dangerously-skip-permissions)",
                                          variable=self.claude_skip_permissions_var)
        skip_perm_check.pack(anchor=tk.W, pady=(5, 5))

        # CLI 상태 확인 버튼
        cli_btn_frame = ttk.Frame(claude_frame)
        cli_btn_frame.pack(fill=tk.X, pady=(5, 0))

        check_cli_btn = tk.Button(cli_btn_frame, text="상태 확인", command=self.check_claude_cli,
                                 bg="#fbbf24", fg="black")
        check_cli_btn.pack(side=tk.LEFT, padx=(0, 5))

        install_cli_btn = tk.Button(cli_btn_frame, text="CLI 설치", command=self.install_claude_cli,
                                   bg="#4ade80", fg="white")
        install_cli_btn.pack(side=tk.LEFT, padx=(0, 5))

        auth_cli_btn = tk.Button(cli_btn_frame, text="CLI 인증", command=self.auth_claude_cli,
                                bg="#6366f1", fg="white")
        auth_cli_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.cli_status_label = tk.Label(cli_btn_frame, text="", bg=self.bg_color, fg=self.fg_color,
                                         font=("Segoe UI", 9))
        self.cli_status_label.pack(side=tk.LEFT, fill=tk.X)

        # IP 내역 프레임
        ip_frame = ttk.LabelFrame(main_frame, text="IP 내역", padding=10)
        ip_frame.pack(fill=tk.X, pady=(0, 10))

        # IP 목록 (성공/실패/차단 상태 포함)
        self.ip_listbox = tk.Listbox(ip_frame, height=4, bg="#0a0a0a", fg=self.fg_color,
                                     selectbackground=self.accent_color, selectforeground="white",
                                     borderwidth=1, relief=tk.SOLID, font=("Consolas", 9))
        self.ip_listbox.pack(fill=tk.X, pady=(0, 5))

        # IP 버튼 프레임 (1행)
        ip_btn_frame1 = ttk.Frame(ip_frame)
        ip_btn_frame1.pack(fill=tk.X, pady=(0, 5))

        refresh_ip_btn = tk.Button(ip_btn_frame1, text="새로고침", command=self.refresh_ip_list,
                                   bg="#6366f1", fg="white")
        refresh_ip_btn.pack(side=tk.LEFT, padx=(0, 5))

        block_btn = tk.Button(ip_btn_frame1, text="수동 차단", command=self.manual_block_selected_ip,
                             bg="#ef4444", fg="white")
        block_btn.pack(side=tk.LEFT, padx=(0, 5))

        unblock_btn = tk.Button(ip_btn_frame1, text="차단 해제", command=self.unblock_selected_ip,
                               bg="#4ade80", fg="white")
        unblock_btn.pack(side=tk.LEFT, padx=(0, 5))

        delete_ip_btn = tk.Button(ip_btn_frame1, text="내역 삭제", command=self.delete_selected_ip_history,
                                 bg="#666", fg="white")
        delete_ip_btn.pack(side=tk.LEFT, padx=(0, 5))

        view_log_btn = tk.Button(ip_btn_frame1, text="로그 보기", command=self.view_login_log,
                                bg="#fbbf24", fg="black")
        view_log_btn.pack(side=tk.RIGHT)

        # UI 설정 프레임
        ui_frame = ttk.LabelFrame(main_frame, text="UI 설정", padding=10)
        ui_frame.pack(fill=tk.X, pady=(0, 10))

        # 자동 스크롤
        self.auto_scroll_var = tk.BooleanVar(value=config["auto_scroll"])
        auto_scroll_check = ttk.Checkbutton(ui_frame, text="자동 스크롤",
                                            variable=self.auto_scroll_var)
        auto_scroll_check.pack(anchor=tk.W)

        # 알림 소리
        self.sound_var = tk.BooleanVar(value=config["sound"])
        sound_check = ttk.Checkbutton(ui_frame, text="알림 소리",
                                      variable=self.sound_var)
        sound_check.pack(anchor=tk.W)

        # 런타임 상태 프레임
        runtime_frame = ttk.LabelFrame(main_frame, text="런타임 상태", padding=10)
        runtime_frame.pack(fill=tk.X, pady=(0, 10))

        # 세션 ID
        session_id_frame = ttk.Frame(runtime_frame)
        session_id_frame.pack(fill=tk.X, pady=2)
        ttk.Label(session_id_frame, text="세션 ID:").pack(side=tk.LEFT)
        self.runtime_session_label = tk.Label(session_id_frame, text="-", bg=self.bg_color, fg="#4ade80",
                                              font=("Consolas", 9))
        self.runtime_session_label.pack(side=tk.RIGHT)

        # 요청 큐
        queue_frame = ttk.Frame(runtime_frame)
        queue_frame.pack(fill=tk.X, pady=2)
        ttk.Label(queue_frame, text="대기열:").pack(side=tk.LEFT)
        self.runtime_queue_label = tk.Label(queue_frame, text="0개", bg=self.bg_color, fg="#fbbf24",
                                            font=("Segoe UI", 9))
        self.runtime_queue_label.pack(side=tk.RIGHT)

        # 처리 상태
        processing_frame = ttk.Frame(runtime_frame)
        processing_frame.pack(fill=tk.X, pady=2)
        ttk.Label(processing_frame, text="처리 상태:").pack(side=tk.LEFT)
        self.runtime_processing_label = tk.Label(processing_frame, text="대기 중", bg=self.bg_color, fg=self.fg_color,
                                                 font=("Segoe UI", 9))
        self.runtime_processing_label.pack(side=tk.RIGHT)

        # 오늘 사용량
        usage_frame = ttk.Frame(runtime_frame)
        usage_frame.pack(fill=tk.X, pady=2)
        ttk.Label(usage_frame, text="오늘 사용량:").pack(side=tk.LEFT)
        self.runtime_usage_label = tk.Label(usage_frame, text="-", bg=self.bg_color, fg="#6366f1",
                                            font=("Segoe UI", 9))
        self.runtime_usage_label.pack(side=tk.RIGHT)

        # 새로고침 버튼
        refresh_runtime_btn = tk.Button(runtime_frame, text="상태 새로고침", command=self.refresh_runtime_status,
                                       bg="#6366f1", fg="white")
        refresh_runtime_btn.pack(anchor=tk.E, pady=(5, 0))

        # 상태 표시
        self.status_label = tk.Label(main_frame, text="서버 중지됨",
                                     font=("Segoe UI", 10),
                                     bg=self.bg_color, fg="#ef4444")
        self.status_label.pack(pady=10)

        # 버튼 프레임
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        self.start_btn = ttk.Button(btn_frame, text="서버 시작", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.stop_btn = ttk.Button(btn_frame, text="서버 중지", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.client_btn = ttk.Button(btn_frame, text="클라이언트 실행", command=self.open_client, state=tk.DISABLED)
        self.client_btn.pack(side=tk.LEFT, padx=(0, 5))

        save_btn = ttk.Button(btn_frame, text="설정 저장", command=self.save_config)
        save_btn.pack(side=tk.RIGHT)

    def load_config_to_gui(self):
        """설정을 GUI에 로드"""
        self.port_var.set(str(config["port"]))
        self.timeout_var.set(str(config["timeout"]))
        self.auto_scroll_var.set(config["auto_scroll"])
        self.sound_var.set(config["sound"])
        self.max_attempts_var.set(str(config.get("max_login_attempts", 5)))
        self.lockout_var.set(str(config.get("lockout_duration", 300)))
        self.max_unblock_var.set(str(config.get("max_auto_unblock", 3)))
        self.session_timeout_var.set(str(config.get("session_timeout", 3600)))

        # Claude CLI 설정 로드
        self.claude_timeout_var.set(str(config.get("claude_timeout", 300)))
        self.claude_workdir_var.set(config.get("claude_working_dir", ""))
        self.claude_skip_permissions_var.set(config.get("claude_skip_permissions", True))

        self.refresh_account_list()
        self.refresh_ip_list()

    def refresh_account_list(self):
        """계정 목록 새로고침"""
        self.account_listbox.delete(0, tk.END)
        for account in config.get("accounts", []):
            self.account_listbox.insert(tk.END, account["id"])

    def refresh_runtime_status(self):
        """런타임 상태 새로고침"""
        global claude_session_id, request_queue, claude_processing

        # 세션 ID
        if claude_session_id:
            self.runtime_session_label.config(text=claude_session_id[:8] + "...")
        else:
            self.runtime_session_label.config(text="-")

        # 요청 큐
        queue_count = len(request_queue)
        self.runtime_queue_label.config(text=f"{queue_count}개")
        if queue_count > 0:
            self.runtime_queue_label.config(fg="#ef4444")
        else:
            self.runtime_queue_label.config(fg="#4ade80")

        # 처리 상태
        if claude_processing:
            self.runtime_processing_label.config(text="처리 중...", fg="#fbbf24")
        else:
            self.runtime_processing_label.config(text="대기 중", fg=self.fg_color)

        # 사용량 조회 (비동기로 처리하면 좋지만 간단히 동기로)
        try:
            usage = get_claude_usage()
            if usage and usage.get("today"):
                today = usage["today"]
                cost = today.get("totalCost", 0)
                self.runtime_usage_label.config(text=f"${cost:.4f} (₩{int(cost * USD_TO_KRW):,})")
            else:
                self.runtime_usage_label.config(text="$0.00")
        except Exception:
            self.runtime_usage_label.config(text="조회 실패")

    def refresh_ip_list(self):
        """IP 내역 목록 새로고침"""
        self.ip_listbox.delete(0, tk.END)
        stats = get_ip_statistics()

        if not stats:
            self.ip_listbox.insert(tk.END, "접속 기록이 없습니다.")
            return

        # 최근 접속 순으로 정렬
        sorted_ips = sorted(stats.items(), key=lambda x: x[1].get("last_access", ""), reverse=True)

        for ip, info in sorted_ips:
            success = info.get("success", 0)
            failed = info.get("failed", 0)
            is_blocked = info.get("is_blocked", False)
            is_permanent = info.get("is_permanent", False)

            # 상태 표시
            if is_blocked:
                if is_permanent:
                    status = "[영구차단]"
                else:
                    status = "[차단중]"
            else:
                status = ""

            line = f"{ip:15} 성공:{success:2} 실패:{failed:2} {status}"
            self.ip_listbox.insert(tk.END, line)

    def refresh_blocked_list(self):
        """이전 호환성 유지"""
        self.refresh_ip_list()

    def unblock_selected_ip(self):
        """선택된 IP 차단 해제"""
        selection = self.ip_listbox.curselection()
        if not selection:
            messagebox.showwarning("경고", "차단 해제할 IP를 선택하세요.")
            return

        idx = selection[0]
        item_text = self.ip_listbox.get(idx)
        ip = item_text.split()[0].strip()

        # 차단 상태 확인
        blocked, _, _ = is_ip_blocked(ip)
        if not blocked:
            messagebox.showwarning("경고", f"IP '{ip}'는 현재 차단 상태가 아닙니다.")
            return

        if messagebox.askyesno("확인", f"IP '{ip}'의 차단을 해제하시겠습니까?"):
            if unblock_ip(ip):
                self.refresh_ip_list()
                messagebox.showinfo("완료", f"IP '{ip}'의 차단이 해제되었습니다.")
            else:
                messagebox.showerror("오류", "차단 해제에 실패했습니다.")

    def delete_selected_ip_history(self):
        """선택된 IP 내역 삭제"""
        selection = self.ip_listbox.curselection()
        if not selection:
            messagebox.showwarning("경고", "삭제할 IP를 선택하세요.")
            return

        idx = selection[0]
        item_text = self.ip_listbox.get(idx)
        ip = item_text.split()[0].strip()

        if messagebox.askyesno("확인", f"IP '{ip}'의 모든 내역을 삭제하시겠습니까?\n(차단 기록 + 로그인 로그)"):
            # blocked_ips.json에서 삭제
            blocked_ips = load_blocked_ips()
            if ip in blocked_ips:
                del blocked_ips[ip]
                save_blocked_ips(blocked_ips)

            # login_log.json에서 해당 IP 로그 삭제
            logs = load_login_log()
            logs = [log for log in logs if log.get("ip") != ip]
            save_login_log(logs)

            # 메모리에서도 삭제
            if ip in login_attempts:
                del login_attempts[ip]

            self.refresh_ip_list()
            messagebox.showinfo("완료", f"IP '{ip}'의 내역이 삭제되었습니다.")

    def manual_block_selected_ip(self):
        """선택된 IP 수동 차단"""
        selection = self.ip_listbox.curselection()
        if not selection:
            # 선택 없으면 직접 입력 다이얼로그
            ip = simpledialog.askstring("IP 차단", "차단할 IP 주소를 입력하세요:", parent=self.root)
            if not ip:
                return
            ip = ip.strip()
        else:
            idx = selection[0]
            item_text = self.ip_listbox.get(idx)
            ip = item_text.split()[0].strip()

        # 이미 차단 상태인지 확인
        blocked, _, is_permanent = is_ip_blocked(ip)
        if blocked and is_permanent:
            messagebox.showwarning("경고", f"IP '{ip}'는 이미 영구 차단 상태입니다.")
            return

        if messagebox.askyesno("확인", f"IP '{ip}'를 영구 차단하시겠습니까?"):
            manual_block_ip(ip)
            self.refresh_ip_list()
            messagebox.showinfo("완료", f"IP '{ip}'가 영구 차단되었습니다.")

    def view_login_log(self):
        """로그인 로그 보기"""
        # 이미 열려있으면 포커스
        if self.log_viewer_dialog is not None and self.log_viewer_dialog.winfo_exists():
            self.log_viewer_dialog.lift()
            self.log_viewer_dialog.focus_force()
            return

        self.log_viewer_dialog = LogViewerDialog(self.root)
        # 창이 닫힐 때 참조 정리
        self.log_viewer_dialog.protocol("WM_DELETE_WINDOW", self._on_log_viewer_close)

    def _on_log_viewer_close(self):
        """로그 뷰어 창 닫기 처리"""
        if self.log_viewer_dialog:
            self.log_viewer_dialog.destroy()
            self.log_viewer_dialog = None

    def browse_working_dir(self):
        """작업 디렉토리 선택"""
        from tkinter import filedialog
        directory = filedialog.askdirectory(
            title="Claude 작업 디렉토리 선택",
            initialdir=self.claude_workdir_var.get() or WORKING_DIR
        )
        if directory:
            self.claude_workdir_var.set(directory)

    def check_claude_cli(self, show_warning=True):
        """Claude CLI 상태 확인"""
        import subprocess

        self.cli_status_label.config(text="확인 중...", fg="#fbbf24")
        self.root.update()

        try:
            # Claude CLI 버전 확인 (Windows에서는 shell=True 필요)
            result = subprocess.run(
                "claude --version",
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                self.cli_status_label.config(text=f"✓ {version}", fg="#4ade80")

                # 인증 상태 확인 (간단한 테스트)
                self._check_claude_auth()
            else:
                self.cli_status_label.config(text="✗ CLI 미설치", fg="#ef4444")
                if show_warning:
                    messagebox.showwarning(
                        "Claude CLI 미설치",
                        "Claude CLI가 설치되지 않았습니다.\n\n"
                        "'CLI 설치' 버튼을 눌러 설치를 진행하세요."
                    )

        except subprocess.TimeoutExpired:
            self.cli_status_label.config(text="✗ 타임아웃", fg="#ef4444")
        except Exception as e:
            self.cli_status_label.config(text=f"✗ 오류: {str(e)[:20]}", fg="#ef4444")

    def _check_claude_auth(self):
        """Claude CLI 인증 상태 확인"""
        import subprocess

        try:
            # 간단한 명령으로 인증 테스트
            result = subprocess.run(
                "claude --help",
                capture_output=True,
                text=True,
                timeout=5,
                shell=True
            )

            if result.returncode == 0:
                current_text = self.cli_status_label.cget("text")
                self.cli_status_label.config(text=f"{current_text} (준비됨)", fg="#4ade80")
        except:
            pass

    def install_claude_cli(self):
        """Claude CLI 설치 (Node.js 확인 후 진행)"""
        import subprocess

        # 1단계: Node.js 확인
        self.cli_status_label.config(text="Node.js 확인 중...", fg="#fbbf24")
        self.root.update()

        node_installed = self._check_nodejs()

        if not node_installed:
            # Node.js 미설치 - 설치 안내
            result = messagebox.askyesno(
                "Node.js 필요",
                "Claude CLI 설치를 위해 Node.js가 필요합니다.\n\n"
                "Node.js가 설치되어 있지 않습니다.\n"
                "Node.js 다운로드 페이지를 열까요?\n\n"
                "(설치 후 이 프로그램을 재시작하세요)"
            )
            if result:
                import webbrowser
                webbrowser.open("https://nodejs.org/")
            self.cli_status_label.config(text="✗ Node.js 필요", fg="#ef4444")
            return

        # 2단계: Claude CLI 이미 설치되어 있는지 확인
        if self._check_claude_installed():
            messagebox.showinfo("알림", "Claude CLI가 이미 설치되어 있습니다.")
            self.check_claude_cli()
            return

        # 3단계: Claude CLI 설치
        result = messagebox.askyesno(
            "Claude CLI 설치",
            "Claude CLI를 설치하시겠습니까?\n\n"
            "명령어: npm install -g @anthropic-ai/claude-code\n\n"
            "설치에 시간이 걸릴 수 있습니다."
        )

        if not result:
            return

        self._run_cli_installation()

    def _check_nodejs(self):
        """Node.js 설치 여부 확인"""
        import subprocess

        try:
            result = subprocess.run(
                "node --version",
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )
            return result.returncode == 0
        except:
            return False

    def _check_claude_installed(self):
        """Claude CLI 설치 여부 확인"""
        import subprocess

        try:
            result = subprocess.run(
                "claude --version",
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )
            return result.returncode == 0
        except:
            return False

    def _run_cli_installation(self):
        """Claude CLI 설치 실행"""
        import subprocess
        import threading

        self.cli_status_label.config(text="설치 중... (잠시 대기)", fg="#fbbf24")
        self.root.update()

        def install_thread():
            try:
                # npm install 실행 (Windows에서는 shell=True 필요)
                result = subprocess.run(
                    "npm install -g @anthropic-ai/claude-code",
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5분 타임아웃
                    shell=True
                )

                # UI 업데이트는 메인 스레드에서
                self.root.after(0, lambda: self._on_install_complete(result))

            except subprocess.TimeoutExpired:
                self.root.after(0, lambda: self._on_install_error("설치 타임아웃"))
            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda msg=error_msg: self._on_install_error(msg))

        # 별도 스레드에서 설치 실행
        thread = threading.Thread(target=install_thread, daemon=True)
        thread.start()

    def _on_install_complete(self, result):
        """설치 완료 처리"""
        if result.returncode == 0:
            self.cli_status_label.config(text="✓ 설치 완료!", fg="#4ade80")
            messagebox.showinfo(
                "설치 완료",
                "Claude CLI가 성공적으로 설치되었습니다.\n\n"
                "처음 사용 시 인증이 필요할 수 있습니다.\n"
                "터미널에서 'claude' 명령어를 실행하여 인증하세요."
            )
            # 상태 다시 확인 (경고 팝업 없이)
            self.check_claude_cli(show_warning=False)
        else:
            error_msg = result.stderr[:200] if result.stderr else "알 수 없는 오류"
            self.cli_status_label.config(text="✗ 설치 실패", fg="#ef4444")
            messagebox.showerror(
                "설치 실패",
                f"Claude CLI 설치 중 오류가 발생했습니다.\n\n{error_msg}"
            )

    def _on_install_error(self, error_msg):
        """설치 오류 처리"""
        self.cli_status_label.config(text="✗ 설치 오류", fg="#ef4444")
        messagebox.showerror("설치 오류", f"설치 중 오류 발생:\n{error_msg}")

    def auth_claude_cli(self):
        """Claude CLI 인증 (터미널 열기)"""
        import subprocess

        # CLI 설치 여부 확인
        if not self._check_claude_installed():
            messagebox.showwarning(
                "CLI 미설치",
                "Claude CLI가 설치되어 있지 않습니다.\n\n"
                "'CLI 설치' 버튼을 눌러 먼저 설치하세요."
            )
            return

        # 터미널에서 claude 실행
        try:
            if sys.platform == "win32":
                # Windows: 새 cmd 창에서 claude 실행
                subprocess.Popen(
                    'start cmd /k "claude"',
                    shell=True
                )
            elif sys.platform == "darwin":
                # macOS: Terminal.app에서 실행
                subprocess.Popen(
                    ['osascript', '-e', 'tell app "Terminal" to do script "claude"']
                )
            else:
                # Linux: 기본 터미널에서 실행
                subprocess.Popen(
                    ['x-terminal-emulator', '-e', 'claude']
                )

            messagebox.showinfo(
                "CLI 인증",
                "터미널 창이 열렸습니다.\n\n"
                "• 인증이 필요한 경우: 안내에 따라 인증을 진행하세요.\n"
                "• 인증이 이미 완료된 경우: Claude 프롬프트가 표시됩니다.\n"
                "  창을 그대로 닫으면 됩니다.\n\n"
                "인증 완료 후 '상태 확인' 버튼을 눌러 확인하세요."
            )
        except Exception as e:
            messagebox.showerror(
                "오류",
                f"터미널을 열 수 없습니다.\n\n"
                f"수동으로 터미널을 열고 'claude' 명령어를 실행하세요.\n\n"
                f"오류: {str(e)}"
            )

    def open_client(self):
        """웹 브라우저에서 클라이언트 열기"""
        import webbrowser

        port = self.port_var.get()
        url = f"http://localhost:{port}/"

        try:
            webbrowser.open(url)
        except Exception as e:
            messagebox.showerror(
                "오류",
                f"브라우저를 열 수 없습니다.\n\n"
                f"수동으로 브라우저에서 {url} 에 접속하세요.\n\n"
                f"오류: {str(e)}"
            )

    def add_account(self):
        """계정 추가"""
        dialog = AddAccountDialog(self.root)
        self.root.wait_window(dialog)

        if dialog.result:
            user_id = dialog.result["id"]
            password = dialog.result["password"]

            # 중복 확인
            for account in config.get("accounts", []):
                if account["id"] == user_id:
                    messagebox.showerror("오류", "이미 존재하는 아이디입니다.")
                    return

            # bcrypt 해시
            hashed = hash_password(password)
            config["accounts"].append({"id": user_id, "password": hashed})
            self.refresh_account_list()
            messagebox.showinfo("완료", f"계정 '{user_id}'가 추가되었습니다.\n설정 저장을 눌러 저장하세요.")

    def delete_account(self):
        """선택된 계정 삭제"""
        selection = self.account_listbox.curselection()
        if not selection:
            messagebox.showwarning("경고", "삭제할 계정을 선택하세요.")
            return

        idx = selection[0]
        user_id = config["accounts"][idx]["id"]

        if messagebox.askyesno("확인", f"계정 '{user_id}'을(를) 삭제하시겠습니까?"):
            del config["accounts"][idx]
            self.refresh_account_list()
            messagebox.showinfo("완료", "계정이 삭제되었습니다.\n설정 저장을 눌러 저장하세요.")

    def save_config(self):
        """GUI에서 설정 저장"""
        try:
            port = int(self.port_var.get())
            timeout = int(self.timeout_var.get())
            max_attempts = int(self.max_attempts_var.get())
            lockout_duration = int(self.lockout_var.get())
            max_auto_unblock = int(self.max_unblock_var.get())
            session_timeout = int(self.session_timeout_var.get())
            claude_timeout = int(self.claude_timeout_var.get())

            if port < 1 or port > 65535:
                raise ValueError("포트는 1-65535 범위여야 합니다.")
            if max_attempts < 1:
                raise ValueError("최대 로그인 시도는 1 이상이어야 합니다.")
            if lockout_duration < 1:
                raise ValueError("차단 시간은 1초 이상이어야 합니다.")
            if max_auto_unblock < 1:
                raise ValueError("최대 자동 해제 횟수는 1 이상이어야 합니다.")
            if session_timeout < 60:
                raise ValueError("세션 만료 시간은 60초 이상이어야 합니다.")
            if claude_timeout < 30:
                raise ValueError("Claude 타임아웃은 30초 이상이어야 합니다.")

            config["port"] = port
            config["timeout"] = timeout
            config["auto_scroll"] = self.auto_scroll_var.get()
            config["sound"] = self.sound_var.get()
            config["max_login_attempts"] = max_attempts
            config["lockout_duration"] = lockout_duration
            config["max_auto_unblock"] = max_auto_unblock
            config["session_timeout"] = session_timeout

            # Claude CLI 설정
            config["claude_timeout"] = claude_timeout
            config["claude_working_dir"] = self.claude_workdir_var.get()
            config["claude_skip_permissions"] = self.claude_skip_permissions_var.get()

            save_config(config)
            messagebox.showinfo("저장", "설정이 저장되었습니다.")
        except ValueError as e:
            messagebox.showerror("오류", str(e))

    def start_server(self):
        """서버 시작"""
        try:
            port = int(self.port_var.get())
            self.server_thread = ServerThread(config["host"], port)
            self.server_thread.start()

            self.status_label.config(text=f"서버 실행 중: http://localhost:{port}/", fg="#4ade80")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.client_btn.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("오류", f"서버 시작 실패: {e}")

    def stop_server(self):
        """서버 중지"""
        if self.server_thread:
            self.server_thread.stop()
            self.server_thread = None

        self.status_label.config(text="서버 중지됨", fg="#ef4444")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.client_btn.config(state=tk.DISABLED)
        self.port_entry.config(state=tk.NORMAL)

    def run(self):
        """GUI 실행"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        """창 닫기 처리"""
        if self.server_thread:
            self.server_thread.stop()
        self.root.destroy()


def main():
    print("=" * 50)
    print("Claude Portable")
    print("=" * 50)

    gui = ConfigGUI()
    gui.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n종료")
