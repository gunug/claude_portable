@echo off
REM Claude Portable ngrok 실행 스크립트
REM 외부 접속을 위한 HTTPS 터널 생성

cd /d "%~dp0"

echo ===============================================
echo Claude Portable - ngrok 터널 실행
echo ===============================================
echo.

REM 포트 설정 (기본값: 8765)
set PORT=8765

REM config.json에서 포트 읽기 시도
for /f "tokens=2 delims=:," %%a in ('type config.json 2^>nul ^| findstr "port"') do (
    set PORT=%%a
    set PORT=!PORT: =!
)

echo 포트: %PORT%
echo.
echo ngrok이 설치되어 있어야 합니다.
echo 설치: https://ngrok.com/download
echo.

REM ngrok 실행
ngrok http %PORT%

pause
