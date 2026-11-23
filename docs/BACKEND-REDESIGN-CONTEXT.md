> 이 문서의 결정은 DESIGN-backend-redesign.md로 대체됨

# 백엔드 재설계 컨텍스트 (2.0.0-beta.13 기준)

작성 시점: 2026-11-23. 새 세션이 이 문서만 읽고 재설계 논의를 시작할 수 있도록 정리한 문서입니다.

## 1. 현재 구조

| 구성요소 | 실행 위치 | 역할 |
|---|---|---|
| UI 앱 (`WindowsAppProtector.WinUI.exe`, Avalonia 11, net8, requireAdministrator) | 사용자 세션, 관리자 | PIN 설정, 앱 목록, 잠금/해제, config.json 저장, 트레이/단축키, 유휴 잠금 |
| 서비스 (`WindowsAppProtector.Service.exe`, .NET Framework csc) | LocalSystem, 세션 0 | 5초마다 `config.json`을 읽어 IFEO 규칙 동기화, 파이프 서버, WindowAgent 감독 |
| Gate (`WindowsAppProtector.Gate.exe`, WinForms) | 사용자 세션, 일반 권한 | IFEO Debugger. `--launch <경로>`는 PIN 창, `--blocked`는 차단 메시지 |
| WindowAgent (`WindowsAppProtector.WindowAgent.exe`, .NET Framework) | 서비스가 사용자 세션에 띄움 | 브라우저/패키지 앱 창을 숨김(창 단위 차단) |
| 명명된 파이프 `\\.\pipe\WindowsAppProtector.Launch.v2` | 서비스가 서버 | Gate 인증/추적, 에이전트 정책 조회, UI의 즉시 동기화 요청 |

잠금 방식은 앱 종류별로 세 가지입니다.
1. 일반 exe: IFEO `Debugger`가 `Gate.exe --blocked`(차단) 또는 `WAP.Launch.N` 하위 키의 `Gate.exe --launch`(PIN 창, `EnableLaunchGate=true`일 때).
2. 브라우저(`WindowOnlyExecutableNames`)와 패키지(UWP) 앱: IFEO를 쓰지 않고 WindowAgent가 창을 숨김.
3. 이미 실행 중인 앱: UI의 `WindowGuardService`/프로세스 종료(`CloseAppsOnLock`).

설정은 `C:\ProgramData\Windows App Protector\config.json`(관리자/SYSTEM만 읽기 가능). 서비스는 DataContractJson, UI는 System.Text.Json으로 같은 파일을 읽고 씁니다.

## 2. 미해결 문제

### P1. 서비스 파이프에 일반/관리자 클라이언트가 접근 불가 (근본 원인 미상)
- 증상: `CreateFile(\\.\pipe\WindowsAppProtector.Launch.v2)`가 항상 `ERROR_ACCESS_DENIED(5)`. 관리자 권한 상승 상태와 SYNCHRONIZE 단독 요청에서도 동일.
- 서버가 로그한 SDDL은 의도대로임: `O:SYG:SYD:P(A;;0x120003;;;IU)(A;;0x120003;;;AU)(A;;0x1f019f;;;SY)`.
- 서버는 클라이언트 요청을 한 번도 받지 못함(연결 이전 단계에서 거부).
- 대조 실험: 같은 DACL의 파이프를 사용자 프로세스가 만들면 접근 성공. 다른 시스템 파이프는 정상. 서비스 SID 타입 NONE, 계정 LocalSystem. 재부팅과 재설치로 바뀌지 않음. Windows 11 Pro 10.0.26300에서 관찰.
- 시도했으나 효과 없음: Authenticated Users ACE 추가, 클라이언트 접근 마스크 정확화, Low 무결성 레이블(생성 시점은 리스너 실패, 생성 후 적용은 무효).
- 미시도 가설: 서비스 토큰 제한(write-restricted 등), 보안 제품/필터 드라이버, 이 OS 빌드의 새 정책, SYSTEM 컨텍스트에서의 직접 재현. (SYSTEM 권한 프로브는 자동 분류기에 의해 거부되어 실행하지 못함)
- 영향: Gate의 PIN 창(`EnableLaunchGate=true`)은 같은 파이프를 쓰므로 사실상 동작 불가로 추정. 현재 사용자 설정은 `EnableLaunchGate=false`라 드러나지 않음. UI의 즉시 정책 동기화도 실패.

### P2. 정책 동기화 경로가 사실상 "5초 폴링" 하나
- UI→서비스 즉시 동기화(`SyncPolicy`)는 P1 때문에 실패하며, 현재는 접근 거부를 "경고 없이 무시"하고 서비스 5초 폴링에 의존.
- 결과: 잠금 직후 최대 5초간 규칙이 반영되지 않는 구간 존재. 서비스가 `config.json` 읽기에 실패하면(과거 이벤트 로그에 파일 사용 중, BOM 오류 기록 있음) 규칙이 오래된 상태로 유지됨.

### P3. 창 단위 차단(WindowAgent)의 취약점
- beta.13에서 창 정책 전달 방식을 바꿨다(세부 내용 삭제). 파이프는 폴백.
- 파이프 예외(`Win32Exception`)가 에이전트를 종료시키던 결함은 폴백 경로에서만 막았음. 에이전트 자체의 오류 보고/로그가 없음.
- 창을 숨기는 방식이라 프로세스는 계속 실행(Chrome 프로세스 25개 유지). 소리/백그라운드 동작/트레이는 막지 못함. 에이전트가 종료되면 보호가 사라짐(감독은 서비스 틱 의존).
- 세션 에이전트는 세션 변경(사용자 전환/RDP)과 서비스 재시작 시 세대(generation) 불일치로 재기동이 필요.

### P4. 이미 실행 중인 앱은 IFEO로 막을 수 없음
- IFEO는 새 실행만 가로챔. 실행 중인 앱은 UI가 떠 있을 때만(`WindowGuardService`, `CloseAppsOnLock`) 처리됨. UI가 종료되면 서비스 단독으로는 실행 중인 일반 exe를 처리하지 못함.

### P5. IFEO 방식 자체의 한계
- 차단 모드 Debugger가 관리자 권한 필수 exe였던 문제는 beta.10에서 Gate `--blocked`로 해결(일반 권한이므로 메시지 표시). 그러나 IFEO 하위 필터 키(`UseFilter`, `FilterFullPath`)는 파일 경로 단위이며, 같은 exe 이름의 다른 앱/업데이트로 경로가 바뀌는 앱, 런처가 자식 프로세스를 띄우는 앱(Electron, Chrome 계열)에서 회피 가능성이 있음.
- 관리자 사용자는 IFEO 키를 직접 지우거나 서비스를 중지할 수 있음(표준 사용자 대상 위협 모델과 관리자 대상의 구분이 문서화되어 있지 않음).
- 서비스의 `SyncRules`는 키에 본인 마커가 없거나 사용자 정의 하위 키가 있으면 해당 앱을 조용히 건너뜀(`continue`). 이 경우 사용자에게 알리지 않음.

### P6. 설정/상태 저장소 이중 구현과 동시성
- 서비스(.NET Framework, DataContractJson)와 UI(.NET 8, System.Text.Json)가 `config.json`을 각자 직렬화. 필드 기본값 규칙이 다름(예: 서비스는 `EnableLaunchGate` 기본 true, 역직렬화 시 true로 초기화).
- 쓰기 충돌 방지는 `settings-write.lock` 임대 방식. 서비스는 읽기만 하지만 UI 쓰기 도중 읽기에서 IOException 가능(이벤트 로그에 과거 기록).
- PIN 해시(PBKDF2 120000회)가 `config.json`에 평문 JSON으로 있음. 접근은 ACL로만 보호.

### P7. 진단/관측성 부족
- 서비스 로그는 `Logs\service.log`(최근 추가), UI는 `protection.log`, `winui-crash.log`. 에이전트와 Gate는 로그 없음. 서비스 예외는 이벤트 로그에만 기록.
- `Logs` 디렉터리와 `config.json`은 관리자만 읽을 수 있어 원격/비관리자 진단이 어려움. 한글 오류 메시지가 인코딩 오류로 깨져 기록됨(`policy-resync-failed ... ?≪꽭?...`).

## 3. 제약과 전제
- 서비스, Gate, WindowAgent는 .NET Framework `csc`(C# 5 수준: `?.`, 문자열 보간, `out var` 사용 불가). UI는 net8 Avalonia(self-contained, 어셈블리 이름 `WindowsAppProtector.WinUI` 유지 — 서비스 경로 검증/설치/제거 스크립트가 의존).
- 서비스는 UI/Gate/에이전트의 exe 경로를 검증해 호출자를 식별(`IsExpectedProcess`). 파이프가 막히면 이 신원 검증 모델 전체가 무효.
- 설치/업데이트: `build_setup.ps1` → `dist/releases/<ver>/Setup.exe` → `gh release create --prerelease`(베타 채널은 Pre-release). 앱 내 업데이트 버튼으로 설치.
- 개발 환경: 비관리자 셸(서비스 로그·config 접근 불가), UAC 프롬프트가 원격에서 보이지 않음. 관리자 진단은 `.scratch/diag.ps1`을 사용자가 실행해 `.scratch/diag-output.txt`로 전달받는 방식.

## 4. 재설계에서 결정해야 할 것
1. IPC 채널 교체: 명명된 파이프 대신 (a) 파일 기반 정책/요청 큐, (b) 로컬 RPC/ALPC, (c) 서비스를 거치지 않는 구조(레지스트리/ACL 보호 파일 + 변경 감시) 중 선택. 호출자 신원 검증을 어떻게 유지할지가 핵심.
2. P1 근본 원인을 규명할지(SYSTEM 컨텍스트 재현 필요), 아니면 파이프를 버릴지.
3. 잠금 집행 주체: 서비스 단일 집행(IFEO + 프로세스 감시 + 창 숨김)으로 통합하고 UI는 설정/표시 전용으로 만들 수 있는지. UI가 꺼져도 실행 중 앱이 잠기도록.
4. 설정 모델 단일화: 하나의 공유 어셈블리/스키마와 버전 관리, 서비스 전용 읽기 모델(PIN 해시와 정책 분리).
5. 위협 모델 명시: 표준 사용자 vs 관리자, 우회 허용 범위, 서비스/에이전트 종료 시의 동작(실패 시 잠금 유지 여부).
6. 에이전트 설계: 창 숨김 대신 프로세스 일시중지/종료 선택지, 세션별 생명주기, 자체 로깅.
7. 진단 체계: 모든 구성요소 공통 로그 위치/포맷(UTF-8), 비관리자도 읽을 수 있는 상태 요약 파일.

## 5. 현재 상태 요약 (사용자 환경, 2026-11-23 검증)
- 설치 버전: 2.0.0-beta.13. 서비스 실행 중, WindowAgent 실행 중, `window-policy.txt` 생성됨(Chrome 경로 포함).
- 카카오톡/millie: IFEO 차단 모드로 정상 차단(`rule ... gate=False -> blocked`).
- Chrome: 창이 숨겨진 것으로 추정(창 핸들 0) — 사용자 시각 확인은 아직 받지 못함.
- 파이프 접근 거부와 즉시 동기화 실패는 여전함(경고 없이 무시 처리 중).
- 미확인: 업데이트 버튼을 통한 설치 흐름의 전 구간, 검은 버튼 글자색/드롭다운 화살표의 실제 가독성, Gate 표시 속도.

## 6. 관련 파일
- `src/Service/WindowsAppProtector.Service.cs` (Tick, SyncRules, PublishWindowPolicyFile)
- `src/Service/LaunchAuthorizationServer.cs` (파이프 서버/ACL/라벨)
- `src/Service/SessionAgentSupervisor.cs` (에이전트 감독)
- `src/LaunchGate/{Program,GateProtocol,GateForm}.cs`, `src/WindowAgent/Program.cs`
- `src/Avalonia/Services/ProtectionService.cs` (UI의 동기화 요청), `src/Avalonia/Platform/WindowGuardService.cs`
- `docs/DESIGN-ui-overhaul.md`, `docs/qa/2.0.0-ui.md`
