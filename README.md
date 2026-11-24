# App PIN Guard

<p align="center">
  <img src="src/Avalonia/Assets/AppIcon.png" alt="App PIN Guard 로고" width="128">
</p>

Windows 앱 실행을 PIN으로 잠그는 데스크톱 도구입니다. 보호 목록에 등록한 `.exe` 앱을 Windows IFEO(Image File Execution Options) 규칙과 창 감시로 차단하고, PIN을 맞힌 앱만 열 수 있게 합니다.

- 기술 스택: Avalonia 11 + .NET 8 (self-contained)
- 최신 공개 버전: **2.0.1** ([릴리즈 노트](https://github.com/droidbin/App-Pin-Guard/releases/tag/v2.0.1))
- 이전 이름: Windows App Protector (1.x 안정판, 2.0부터 App PIN Guard로 변경)

## 설치

최종 배포 파일은 `Setup.exe` 하나입니다. 실행하면 관리자 권한을 요청한 뒤 다음 작업을 자동으로 처리합니다.

- 실행 중인 기존 보호 프로그램 프로세스 종료
- 이전 버전이 남긴 관리형 IFEO 차단 규칙 정리
- 기존 설치 폴더와 바로가기·시작 작업·제거 등록 정리
- PIN, 사용자 설정, 보호 앱 목록 보존
- 새 설치 파일의 압축·필수 파일·앱 실행을 검증한 뒤 `C:\Program Files\Windows App Protector <버전>`에 설치
- .NET 및 Avalonia 런타임을 앱 폴더에 포함하므로 설치 중 별도 런타임 설치나 인터넷 연결이 필요 없음
- 기존 버전 제거에 실패하면 새 설치 중단
- 바탕화면·시작 메뉴 바로가기 생성(선택), Windows 앱 제거 목록 등록, 설치 후 앱 실행

## 주요 기능

- 여러 `.exe` 앱 보호 목록 관리, 앱 단위 잠금/해제
- 목록 전체 잠금/해제, 전역 단축키 등록 및 중복 감지
- 앱 실행 및 백그라운드 복귀 시 PIN 인증
- 앱 단위 잠금 해제: PIN을 한 번 입력하면 해당 앱의 모든 창이 열리고, 다른 잠긴 앱은 계속 잠겨 있음
- 실행 중인 잠긴 앱은 닫을 때까지 해제 상태 유지 (카카오톡 등 다중 프로세스 앱 포함)
- 스토어(MSIX/패키지) 앱도 잠금 및 PIN 해제 지원
- 앱 목록에서 현재 잠금 해제되어 사용 중인 앱 표시
- 일정 시간 유휴 상태일 때 보호 목록 자동 잠금
- 잠금 시 실행 중인 앱 종료 옵션
- Win32 실행 PIN (실험 기능, 설정에서 켬): 보호 앱을 직접 실행할 때 Launch Gate가 PIN을 요구
- Windows 시작 시 자동 실행 ON/OFF
- 창 닫기 시 백그라운드 트레이 아이콘으로 전환, 메뉴에서 종료 시 백그라운드 프로세스까지 종료
- Windows Service 기반 보호 규칙 감시 및 복구
- GitHub Releases 기반 자동 업데이트 (`Setup.exe` SHA-256 검증 후 설치)
- 베타/정식 업데이트 채널 선택

## 기본 단축키

- `Ctrl+Alt+W`: 창 보이기/숨기기
- `Ctrl+Shift+L`: 목록 잠금
- `Ctrl+Shift+U`: 목록 해제

## 차단 방식

보호 기능은 아래 레지스트리에 관리형 규칙을 등록해서 동작합니다.

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

Chrome, Edge, Samsung Internet 같은 브라우저와 스토어/MSIX 앱은 세션 에이전트(`WindowsAppProtector.WindowAgent.exe`)가 창을 감시합니다. 브라우저는 등록한 실행 파일의 전체 경로, 스토어/MSIX 앱은 패키지 패밀리 이름으로 판정합니다. 잠금 중에는 창을 숨기며 프로세스 자체는 그대로 둡니다.

차단된 앱을 새로 실행하면 대상 앱을 강제 종료하지 않고 실행만 막습니다. 잠금 시 앱 종료 옵션을 켜면 Win32 보호 앱에 정상 종료를 요청하고 5초 대기합니다. 종료를 거부하는 앱은 강제 종료하지 않으며, 저장되지 않은 작업은 손실될 수 있습니다.

Windows 시작 시 자동 실행은 관리자 권한 앱이 로그인 후 안정적으로 실행되도록 `Windows App Protector` 예약 작업으로 등록합니다. 이전 버전의 HKCU Run 등록은 설정 저장 시 자동으로 정리됩니다.

설계 상세는 [잠금 재설계 문서](docs/DESIGN-app-lock-redesign.md)를 참고하세요.

## 보호 서비스

설치 시 `WindowsAppProtectorService`가 자동 시작 서비스로 등록됩니다.

서비스는 `%PROGRAMDATA%\Windows App Protector\config.json`을 기준으로 보호 상태를 감시하고, 사용자가 UI 프로세스를 작업 관리자에서 강제 종료해도 관리형 IFEO 규칙을 주기적으로 복구합니다. 로그인한 세션에는 사용자 권한으로 창 감시 에이전트를 실행하고, 종료되면 다시 시작합니다. 관리 화면을 닫아도 창 감시는 계속됩니다.

- ProgramData 설정은 관리자와 SYSTEM만 수정할 수 있으며, 서비스는 이 신뢰 경로만 읽습니다.
- PIN 해시는 PBKDF2-SHA256과 고정 시간 비교로 확인합니다.
- 설정·PIN 해시 저장 위치: `%PROGRAMDATA%\Windows App Protector\config.json`
- 1.x 설정은 처음 실행 시 한 번 이전합니다. 공유 폴더에 등록된 보호 정책을 우선하며, 1.x 복귀용 기존 파일은 그대로 남습니다.

## 빌드

개발 PC에서 아래 명령을 실행하면 앱과 설치 파일이 생성됩니다.

```powershell
.\build_setup.bat
```

빌드 결과:

```text
dist\installer\Setup.exe
```

앱 실행 파일만 빌드하려면 `build_app.bat`을 사용합니다.

## 업데이트 배포

자동 업데이트는 GitHub Releases의 최신 릴리즈를 기준으로 동작합니다.

- 버전 규칙: 메이저 업데이트는 1 단위(`2.0.0`), 마이너 업데이트는 0.1 단위(`1.3.0`), 버그 수정은 세 번째 자리를 올립니다(`2.0.0` → `2.0.1`).
- 안정판 릴리즈 태그는 `v2.0.1`처럼 앱 버전과 맞춥니다.
- 배포 채널은 **베타**와 **정식** 두 가지입니다. 베타는 `2.0.0-beta.N`으로 표기하고 GitHub 사전 릴리즈로 공개합니다. 정식 채널은 접미사 없는 버전입니다.
- 릴리즈 자산은 `Setup.exe`이며, 자동 업데이트는 자산의 SHA-256 digest를 확인합니다.
- 새 버전 설치 시 기존 설치 폴더를 제거합니다. 기존 릴리즈·태그·자산은 보존합니다.
- 안정판을 게시하기 전 Windows 빌드, 자동 업데이트 해시 검증, 설치·업그레이드·재부팅 동작을 확인합니다.
- GitHub Actions의 Windows 빌드 검증은 자동 릴리스 게시를 수행하지 않습니다.
- private 저장소를 사용할 경우 `WINDOWS_APP_PROTECTOR_GITHUB_TOKEN` 환경 변수 또는 `%PROGRAMDATA%\Windows App Protector\github-token.txt`에 GitHub 토큰을 넣어야 합니다.

## 개발 및 운영

- 작업은 최신 안정판에서 분기한 `codex/` 또는 `beta/` 브랜치에서 진행합니다.
- 변경 사항은 Windows 빌드와 단위 테스트(`tests/UnitTests`)로 검증하고, 베타 버전 식별자와 검증 결과를 기록합니다.
- 검증 전에는 안정판 태그, GitHub Release, 설치 파일을 게시하지 않습니다.

## 제거

Windows 설정의 앱 목록에서 제거하거나 설치 폴더의 `uninstall.bat`을 실행하면 됩니다.

제거 시 Windows Service, 시작 예약 작업, 관리형 IFEO 규칙, 서비스 설정, 바로가기가 함께 정리됩니다.

내부 실행 파일·서비스 이름(`WindowsAppProtector.*`, `WindowsAppProtectorService`)과 `%PROGRAMDATA%\Windows App Protector` 경로는 현재 코드의 식별자이므로 제품명 변경과 무관하게 그대로 유지합니다.
