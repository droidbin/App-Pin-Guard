# 백엔드 재설계 구현 명세 (2.0.0-beta.13 기준)

> **구현 AI에게**: 이 문서는 한 번에 일괄 구현하라고 쓴 명세입니다. 단계를 나누지 않습니다. 중간 빌드나 중간 보고, 질문 없이 §9의 변경 목록 전체를 반영한 뒤 마지막에 한 번 빌드하고, §10 체크리스트로 결과를 보고하세요. §11 "확정된 결정"은 다시 논의하지 않습니다. 문서에 없는 세부 사항은 "더 단순하고, 실패하면 잠금이 유지되는 쪽"을 고르고 보고서에 적으세요.
> 배경 자료는 `docs/BACKEND-REDESIGN-CONTEXT.md`(P1~P7 문제 정의)와 `docs/DESIGN-rename-bypass.md`입니다.

---

## 1. 목표

1. **명명된 파이프를 모든 경로에서 제거합니다.** P1(원인 불명의 `ACCESS_DENIED`)을 고치려 하지 않고, 동작이 확인된 메커니즘으로만 다시 구성합니다. 확인된 메커니즘은 서비스가 만든 커널 이벤트(에이전트가 이미 열고 있음), ACL로 보호한 파일, `CreateProcessAsUser`입니다.
2. **집행 주체를 서비스 하나로 모읍니다.** UI는 설정을 편집하고 상태를 보여주기만 합니다. UI가 꺼져 있어도 잠금, 실행 중 앱 처리, 우회 차단이 동작해야 합니다.
3. **설정 모델을 하나로 합칩니다.** 스키마 소스 파일 하나를 모든 구성요소가 컴파일하고, 직렬화기도 하나만 씁니다. 정책과 비밀(PIN 해시)은 분리합니다.
4. **잠금 반영 지연을 없애고, 반영 여부를 확인할 수 있게 합니다.** 저장한 뒤 1초 안에 반영되어야 하고, 반영되었는지 UI가 확인할 수 있어야 합니다.
5. **진단 기능을 갖춥니다.** 모든 구성요소가 같은 UTF-8 로그 형식을 쓰고, 관리자가 아니어도 읽을 수 있는 상태 파일을 둡니다.

비목표: 커널 드라이버, 관리자 대상 방어, 새 UI 화면 설계(상태 표시 요소만 추가합니다), 버전 변경과 릴리스.

---

## 2. 위협 모델 (이 문서에서 확정)

| 행위자 | 방어 여부 | 근거 |
|---|---|---|
| 같은 PC의 **표준 사용자**(관리자 아님) 또는 권한 상승하지 않은 세션 | **방어 대상** | 제품이 존재하는 이유 |
| 권한 상승할 수 있는 **관리자** | 방어하지 않음. 변조는 **탐지해서 복구하고 표시**만 함 | 서비스 중지, 레지스트리 삭제, 드라이버 설치 등 막을 방법이 없음 |

방어 대상 행위자에 대해 다음을 보장합니다.

- 잠긴 일반 exe를 다음 방법으로 실행해도 PIN 없이는 사용할 수 없습니다.
  - 정상 실행: IFEO가 Gate를 띄웁니다.
  - `DEBUG_PROCESS` 플래그로 실행해 IFEO를 우회하는 경우
  - 이름을 바꾸거나 다른 위치에 복사해서 실행하는 경우
  - 위 우회는 모두 프로세스 감시기가 종료합니다.
- 잠긴 앱의 창은 보이지 않습니다. 이미 실행 중이던 앱도 마찬가지입니다.
- 표준 사용자는 다음을 할 수 없습니다.
  - 창 에이전트 종료
  - 정책 파일 수정
  - 다른 사용자의 Gate 요청 읽기
  - PIN 해시 읽기
- **실패할 때는 잠금을 유지합니다(fail-closed).**
  - 서비스가 멈춰도 IFEO 규칙은 남아 있습니다.
  - 서비스가 응답하지 않으면 Gate는 실행을 거부합니다.
  - 에이전트가 비정상 종료해도 숨긴 창을 복원하지 않습니다.
  - 창 복원은 오직 "정책상 해제"일 때만 일어납니다.

이 표는 그대로 `docs/THREAT-MODEL.md`로 옮기고 README의 보안 절에서 링크합니다.

---

## 3. 목표 아키텍처

```
┌──────────── 사용자 세션 ────────────┐        ┌──────────── 세션 0 ────────────────────────┐
│ UI (관리자)                          │        │ 서비스 (LocalSystem)                         │
│  편집 → policy.json / secrets.json   │─파일──▶│  PolicyHost: 이벤트·파일 감시·5초 타이머     │
│  SetEvent(Global\WAP.PolicyChanged)  │─이벤트▶│  RuleEngine: IFEO 동기화 + 레지스트리 감시   │
│  Runtime\status.json 읽기 ◀──────────┼────────│  ProcessWatcher: WMI 시작 이벤트 + 1초 스윕  │
│                                      │        │  GrantTable: Gate 승인·추적                  │
│ Gate (일반 권한)                      │        │  GateSpoolServer: 요청 처리                  │
│  Gate\Requests\*.req 쓰기 ───────────┼──────▶ │  AgentSupervisor: 세션별 에이전트 감독       │
│  Gate\Responses\*.res 읽기 ◀─────────┼────────│  StatusWriter: Runtime\status.json           │
│                                      │        │                                              │
│ WindowAgent (사용자 토큰, 종료 불가)  │        │                                              │
│  Runtime\enforcement.txt 읽기 ◀──────┼────────│  (서비스가 씀)                                │
│  Global\WAP.EnforcementChanged 대기  │        │  CreateProcessAsUser: 에이전트, Gate 표시     │
└──────────────────────────────────────┘        └──────────────────────────────────────────────┘
```

### 3.1 채널

| 방향 | 채널 | 대체 경로 |
|---|---|---|
| UI → 서비스 (정책 변경) | `policy.json` 원자적 교체 후 `Global\WAP.PolicyChanged` 이벤트 | 서비스의 `FileSystemWatcher`, 그다음 5초 타이머 |
| 서비스 → UI (반영 확인) | `Runtime\status.json`의 `AppliedRevision` | 없음(읽기 전용) |
| 서비스 → 에이전트 | `Runtime\enforcement.txt` + `Global\WAP.EnforcementChanged` | 에이전트의 2초 폴링 |
| Gate → 서비스 (PIN 인증, 추적) | 요청/응답 파일 스풀(§6) | 없음. 응답이 없으면 실행을 거부함 |
| 서비스 → 사용자 세션 (Gate 표시) | `CreateProcessAsUser(Gate.exe ...)` | 없음 |

### 3.2 디렉터리 레이아웃과 ACL

루트는 `C:\ProgramData\Windows App Protector\`입니다. 서비스가 시작할 때마다 `SecureLayout.Ensure()`로 아래 ACL을 강제합니다. 상속은 끄고 소유자는 SYSTEM으로 둡니다.

| 경로 | SYSTEM | Administrators | Users | 비고 |
|---|---|---|---|---|
| `policy.json` | 모든 권한 | 모든 권한 | — | 앱 목록과 잠금 설정 |
| `secrets.json` | 모든 권한 | 모든 권한 | — | PIN 해시 |
| `ui.json` | 모든 권한 | 모든 권한 | — | 단축키, 유휴 시간, 업데이트 채널 등 UI 전용 |
| `Runtime\` | 모든 권한 | 모든 권한 | 읽기 | `enforcement.txt`, `status.json` |
| `Runtime\attempts\` | 모든 권한 | 모든 권한 | — | SID별 PIN 실패 횟수 |
| `Gate\Requests\` | 모든 권한 | 모든 권한 | **이 폴더에만 파일 만들기** | `CREATOR OWNER`에 파일 단위 모든 권한(상속 전용) |
| `Gate\Responses\` | 모든 권한 | 모든 권한 | — | 응답 파일마다 요청자 SID에 읽기 ACE를 명시 |
| `Logs\` | 모든 권한 | 모든 권한 | 읽기 | 로그에 PIN, 해시, 요청 원문을 절대 쓰지 않음 |

`Policy\window-policy.txt`와 그 폴더는 이번 재설계로 폐기합니다. 서비스가 시작할 때 삭제합니다.

---

## 4. 공유 코어 `src/Shared/` (C# 5 문법)

모든 파일은 C# 5로 작성합니다. `?.`, 문자열 보간, `out var`, 식 본문, `nameof`는 쓰지 않습니다. 파일 맨 위에 `#nullable disable`을 넣지 마세요. csc가 인식하지 못합니다. net8 프로젝트에서는 csproj의 `<Compile Include ... Link>`로 포함하고, 이 파일들에 대해서만 `<NoWarn>` 또는 `Nullable=disable`인 별도 ItemGroup 설정으로 경고를 억제합니다.

| 파일 | 내용 |
|---|---|
| `ProductBrand.cs` | 기존 파일 유지 |
| `WapPaths.cs` | §3.2의 모든 경로와 이벤트 이름(`Global\WAP.PolicyChanged`, `Global\WAP.EnforcementChanged`, `Global\WAP.AgentStop`) 상수. 다른 곳에 경로 문자열을 직접 쓰지 않음 |
| `WapLog.cs` | 로거(§8) |
| `PolicyModel.cs` | `PolicyDocument`, `AppPolicy`, `LaunchPolicy`, `SecretsDocument`, `PinRecord`(DataContract) |
| `PolicyStore.cs` | 읽기와 원자적 쓰기, BOM 허용, 재시도, revision 관리 |
| `PolicyRules.cs` | 브라우저 이름 목록(현재 서비스와 UI에 중복된 `WindowOnlyExecutableNames`), `GetMode(app)`, `GetRuleName(app)`, `IsWithinLockHours`, 경로 정규화 |
| `PinHash.cs` | PBKDF2-SHA256 해시 생성과 검증(고정 시간 비교). UI의 `PinHasher`와 서비스의 `LaunchAttemptState.Verify`를 이것으로 대체 |
| `GateSpool.cs` | 요청과 응답 형식, 직렬화, 파싱(§6) |
| `StatusModel.cs` | `status.json` 스키마 |
| `EnforcementFile.cs` | `enforcement.txt` 형식 쓰기/읽기(§7.4) |

### 4.1 스키마

```
PolicyDocument (policy.json)
  SchemaVersion   int    = 3
  Revision        long   // UI가 저장할 때마다 +1. 서비스는 적용한 값을 status에 기록
  EnableLaunchGate bool  = true
  CloseAppsOnLock bool   = false
  Apps            AppPolicy[]

AppPolicy
  Id              string // GUID "N". 마이그레이션할 때 생성. 비밀·승인·상태의 키
  Name, Path, IsPackaged, PackageFamilyName, AppUserModelId, ExecutableName  (기존과 같음)
  Locked          bool   // 기존 Enabled. 이름을 바꿔 의미를 분명히 함
  LockedAtUtc     string // ISO-8601. UI가 Locked를 false→true로 바꿀 때 기록
  FileSize        long   // 등록하거나 갱신할 때 UI가 기록. 0이면 해시 검사 생략
  Sha256          string // 같은 시점에 기록. 소문자 hex
  Launch          LaunchPolicy { AllowedMinutes, LockStartMinute?, LockEndMinute?, RelockOnExit, HasOwnPin }

SecretsDocument (secrets.json)
  SchemaVersion = 1
  AppPin          PinRecord { Salt, Hash, Iterations = 120000 }
  AppPins         Dictionary<AppId, PinRecord>   // 앱별 PIN
```

- 기본값은 생성자와 `[OnDeserializing]`에서 **똑같이** 설정합니다. 현재 서비스는 `EnableLaunchGate`를 역직렬화할 때 true로 초기화하는데, 이런 불일치를 없앱니다.
- 알 수 없는 `SchemaVersion`이 오면 예외를 던집니다. 서비스는 이 경우 **마지막으로 정상이던 정책을 유지**하고 status에 오류를 기록합니다.

### 4.2 PolicyStore 규칙

- 쓰기 순서:
  1. 같은 폴더에 `name.<guid>.tmp`를 UTF-8(BOM 없음)로 씁니다.
  2. `Flush(true)`로 디스크에 내립니다.
  3. `File.Replace`로 교체합니다. 대상 파일이 없으면 `File.Move`를 씁니다.
- 쓰기 경합은 이름 있는 뮤텍스 `Global\WAP.PolicyWrite`로 막습니다(SYSTEM과 Administrators만 접근). 기존 `settings-write.lock` 임대 방식은 삭제합니다.
- 읽기는 `FileShare.ReadWrite | FileShare.Delete`로 엽니다. `IOException`이 나면 50, 100, 200ms 간격으로 세 번 재시도합니다. 맨 앞의 UTF-8 BOM은 건너뜁니다.
- 직렬화기는 양쪽 모두 `DataContractJsonSerializer`를 씁니다. net8에도 이 직렬화기가 있으므로 UI의 System.Text.Json 정책 직렬화는 제거합니다. `ui.json`은 UI 전용이므로 System.Text.Json을 계속 써도 됩니다.

---

## 5. 서비스 재구성 (`src/Service/`)

`WindowsAppProtector.Service.cs`(980줄)를 아래 파일로 나눕니다. 각 클래스는 생성자 주입 없이 `ProtectionWorker`가 조립합니다.

| 파일 | 책임 |
|---|---|
| `ServiceHost.cs` | `ServiceBase`, `Main`, `OnSessionChange`에서 에이전트 즉시 재조정 |
| `ProtectionWorker.cs` | 조립과 수명 관리. 아래 구성요소를 순서대로 시작하고 역순으로 멈춤 |
| `SecureLayout.cs` | 디렉터리 생성, ACL 강제, 레거시 파일 정리 |
| `PolicyHost.cs` | 정책을 불러와 "마지막 정상 정책"으로 보관. 트리거 세 가지(이벤트, 감시, 5초)를 하나의 직렬화된 `Apply()`로 합침 |
| `RuleEngine.cs` | 기존 `SyncRules`와 레거시 SRP 정리 코드를 옮김 + 충돌 보고 + IFEO 레지스트리 변경 감시 |
| `ProcessWatcher.cs` | §7.1 |
| `GrantTable.cs` | 기존 `launchGrants`/`pendingLaunches` 로직을 AppId 키로 옮김 |
| `GateSpoolServer.cs` | §6 |
| `AgentSupervisor.cs` | §7.3 (기존 `SessionAgentSupervisor` 대체) |
| `SessionLauncher.cs` | `CreateProcessAsUser` 공통 코드. 에이전트 실행과 Gate 알림 표시에 같이 씀 |
| `StatusWriter.cs` | §8.2 |

삭제할 파일: `LaunchAuthorizationServer.cs` 전체(파이프, Low 레이블, `IsExpectedProcess`)와 `LaunchGate/GateProtocol.cs`의 파이프 코드.

### 5.1 PolicyHost.Apply() 순서

1. `policy.json`과 `secrets.json`을 읽습니다. 실패하면 마지막 정상 정책을 그대로 쓰고 `status.PolicyError`에 기록합니다.
2. Locked 상태가 바뀐 앱을 계산합니다(이전 정책과 비교).
3. `RuleEngine.Sync(policy)`를 호출합니다.
4. `GrantTable.Prune(policy)`를 호출합니다. 해제되었거나 삭제된 앱의 승인을 정리합니다.
5. `ProcessWatcher.OnPolicyChanged(policy, transitions)`를 호출합니다(§7.1의 "잠금 전환" 처리).
6. `enforcement.txt`를 다시 쓰고 `Global\WAP.EnforcementChanged`를 신호합니다.
7. `status.AppliedRevision = policy.Revision`으로 두고 status를 씁니다.

`Apply()`는 `lock` 하나로 직렬화합니다. 트리거가 몰려도 100ms 디바운스로 한 번만 실행합니다.

### 5.2 RuleEngine 변경점

- 기존 IFEO 키 구조(`WindowsAppProtectorManaged` 마커, `WAP.Launch.N` 필터, `Gate.exe --blocked`)는 그대로 유지합니다. 설치 제거 스크립트가 이 구조에 의존합니다.
- 다음 두 경우에는 조용히 `continue`하지 않습니다. 해당 앱을 `status.Apps[id].Rule = "conflict"`로 기록하고 로그를 남깁니다.
  - 남의 키에 `Debugger`/`UseFilter`가 있는 경우
  - 마커 없는 하위 키가 있는 경우
- 적용 결과는 앱마다 `applied-gate` | `applied-blocked` | `window-mode` | `conflict` | `error:<code>` 중 하나입니다.
- 자가 복구: 별도 스레드에서 IFEO 루트에 `RegNotifyChangeKeyValue(subtree)`를 겁니다. 변경이 감지되면 `Apply()`를 트리거하고, 관리 키가 사라졌다면 `status.TamperEvents`에 시각과 앱 이름을 추가합니다(최근 20개).
- `uiPath`가 없으면 동기화를 건너뛰는 현재 조건은 삭제합니다. 차단기는 항상 Gate이고, Gate가 없으면 `status.Healthy=false`로 기록합니다.
- 서비스가 중지될 때(`OnStop`) **규칙을 지우지 않습니다**. 규칙은 설치 제거 시에만 지웁니다.

---

## 6. Gate ↔ 서비스: 파일 스풀

### 6.1 요청 (Gate가 씀)

`Gate\Requests\<nonce>.req`를 `FileMode.CreateNew`로 만듭니다. `nonce`는 `RandomNumberGenerator`로 만든 16바이트의 hex입니다. 내용은 UTF-8 텍스트이고 줄 구분은 `\n`입니다.

```
WAP-GATE 1
op=authorize | track
nonce=<32 hex>
pid=<Gate 자신의 PID>
path=<base64(UTF-8 전체 경로)>
pin=<base64(UTF-8 PIN)>        # authorize에서 PIN 입력 후. 첫 조회는 빈 값
child=<PID>                    # track에서만
```

파일 크기는 8KB를 넘지 않습니다.

### 6.2 서비스 처리 (GateSpoolServer)

- `FileSystemWatcher(Created)`와 300ms 주기 디렉터리 스캔을 함께 씁니다. 감시 버퍼가 넘쳐도 처리되도록 하기 위해서입니다.
- 파일마다 다음 순서로 처리합니다.
  1. 파일을 엽니다.
  2. **소유자 SID**를 읽습니다.
  3. 내용을 읽습니다.
  4. **즉시 삭제합니다**(PIN이 디스크에 남는 시간을 최소화).
- 다음 신원 검증을 모두 통과해야 하고, 하나라도 실패하면 `denied`로 응답합니다.
  - `pid` 프로세스가 살아 있고, 이미지 경로가 설치된 `Gate.exe`와 같아야 합니다.
  - 그 프로세스의 사용자 SID가 파일 소유자 SID와 같아야 합니다. 관리자가 만든 파일은 소유자가 Administrators일 수 있으므로, 이때는 프로세스 토큰의 사용자 SID를 씁니다.
  - 세션 ID가 0보다 커야 합니다.
  - 기존 `IsExpectedProcess`보다 약하지 않습니다. 프로세스 신원과 사용자 신원을 모두 확인하기 때문입니다.
- 판정 로직은 기존 `HandleLaunchRequest`를 그대로 옮깁니다(시간대, 승인 유지, 실패 횟수 제한, 앱별 PIN). 키만 경로 대신 `AppId`로 바꿉니다.
- 실패 횟수 상태는 `Runtime\attempts\<sid>.json`에 둡니다.

### 6.3 응답 (서비스가 씀)

`Gate\Responses\<nonce>.res`를 임시 파일에 먼저 쓰고, 요청자 SID 읽기 ACE를 단 뒤 이름을 바꿉니다. 내용은 다음과 같습니다.

```
WAP-GATE 1
nonce=<같은 값>
result=approved | denied | prompt | ratelimited | unavailable
retryAfter=<초>                 # ratelimited일 때
```

- Gate는 응답을 50ms 간격으로 최대 4초 기다립니다.
- 응답 파일의 **소유자가 SYSTEM이 아니면 무시합니다**. nonce가 다르면 무시합니다.
- 읽은 뒤에는 Gate가 응답 파일을 삭제합니다. 서비스는 1분이 지난 요청과 응답을 청소합니다.
- 4초 안에 응답이 없으면 "보호 서비스가 응답하지 않아 실행할 수 없습니다"를 표시하고 **실행하지 않습니다**.

### 6.4 Gate 변경점 (`src/LaunchGate/`)

- `Program.Exchange`의 구현을 `GateSpool` 클라이언트로 바꿉니다. 화면(`GateForm`/`GateTheme`)은 그대로 둡니다.
- 새 인자 `--notice-blocked <경로>`를 추가합니다. 서비스가 감시기로 프로세스를 종료한 뒤 사용자 세션에 띄우는 안내입니다. `--blocked`와 같은 화면을 쓰되 문구는 "PIN Guard가 잠긴 앱의 실행을 막았습니다"입니다.
- Gate 모드인 앱이라면 서비스는 `--launch <경로>`를 대신 띄워 바로 PIN을 입력할 수 있게 합니다.
- Gate 로그는 `%LOCALAPPDATA%\WindowsAppProtector.WinUI\Logs\gate.log`(§8)에 씁니다.

---

## 7. 집행

### 7.1 ProcessWatcher (서비스)

입력은 두 가지입니다.

- 실시간: `System.Management`로 `Win32_ProcessStartTrace`를 구독합니다. 이벤트에서 `ProcessID`, `ParentProcessID`, `SessionID`를 받습니다.
- 백스톱: 1초마다 프로세스 스냅샷을 비교해 새로 생긴 PID를 처리합니다. WMI 이벤트가 누락되거나 공급자가 재시작되는 경우에 대비합니다.
- WMI 구독이 실패하면 로그를 남기고 스냅샷만으로 동작합니다. `status.Watcher = "polling"`으로 표시합니다.

새 프로세스는 `세션 > 0`이고 이미지 경로를 얻을 수 있는 경우에만 판정합니다(`QueryFullProcessImageName`).

1. 경로가 잠긴 일반 exe 앱(Mode=launch)의 `Path`와 같으면 그 앱으로 판정합니다.
2. 경로는 다르지만 `FileSize`가 같고 SHA-256도 같으면 같은 앱으로 판정합니다. 이름 변경이나 복사 우회에 해당합니다.
   - 해시는 `(경로, 크기, 수정 시각)` 키로 캐시합니다.
   - 크기가 다르면 해시를 계산하지 않습니다.
   - 64MB를 넘는 파일은 해시 검사를 생략하고 로그만 남깁니다.
3. 판정된 앱이 있으면 다음 중 하나라도 해당할 때 허용합니다.
   - 시간대 정책상 잠금 시간이 아닌 경우
   - `GrantTable`에 PID(+시작 시각)가 등록된 경우
   - 부모 PID가 같은 앱으로 승인된 프로세스인 경우. Electron이나 Chrome처럼 같은 exe를 자식으로 띄우는 앱을 위한 규칙입니다.
   - 부모 PID가 직전 5초 안에 이 앱에 대해 `authorize`로 승인받은 Gate 프로세스인 경우. `track`이 도착하기 전에 감시기가 Gate의 자식을 먼저 보는 경합 때문에 필요합니다. 이 경우 그 자식을 즉시 승인 목록에 등록합니다.
4. 허용되지 않으면 `TerminateProcess`로 종료하고, 그 세션에 Gate를 띄웁니다(§6.4). 같은 앱의 안내는 10초에 한 번만 띄웁니다.

Mode=window(브라우저, 패키지 앱)는 감시기가 종료하지 않습니다. 창은 에이전트가 숨깁니다.

**잠금 전환**(Locked false→true, `OnPolicyChanged`)은 다음과 같이 처리합니다.

- `CloseAppsOnLock = true`이면 해당 앱의 실행 중 프로세스를 처리합니다. 에이전트가 먼저 창을 닫도록(`WM_CLOSE`) 정책에 표시하고, 5초 뒤에도 남아 있는 프로세스는 서비스가 종료합니다.
- false이면 `LockedAtUtc` 이전에 시작된 프로세스는 종료하지 않습니다. 대신 에이전트가 창을 숨깁니다(기존 UI `WindowGuardService`의 동작을 서비스 쪽으로 옮긴 것). `LockedAtUtc` 이후에 시작되었고 승인이 없는 프로세스는 3번 규칙대로 종료합니다.

**해제 전환**(Locked true→false)에서는 에이전트가 숨긴 창을 복원합니다. 종료된 프로세스는 되살리지 않습니다.

### 7.2 GrantTable

> **→ `DESIGN-app-lock-redesign.md`로 대체됨.** 해제 단위가 PID에서 앱(`UnlockTable`)으로 바뀌었고 `GrantTable`, `track`은 삭제되었습니다. 아래는 이력으로만 남깁니다.

기존 메모리 승인 로직(유효 시간, `RelockOnExit`, track 5초 창)을 유지합니다. 다음 세 가지만 추가합니다.

- `track`으로 등록한 PID와 시작 시각의 쌍을 감시기가 조회할 수 있게 합니다.
- 정책이 바뀌어 해당 앱이 해제되거나 PIN이 바뀌면 승인을 제거합니다. 키에 해시를 넣던 기존 방식은 AppId와 PIN 레코드 버전으로 대체합니다.
- 승인된 PID 목록은 `enforcement.txt`에도 실어, 에이전트가 그 창을 숨기지 않게 합니다.

### 7.3 AgentSupervisor와 WindowAgent

**감독(서비스)**

- 세대 GUID를 폐기합니다. 정지 이벤트는 고정 이름 `Global\WAP.AgentStop`을 쓰고 에이전트에는 SYNCHRONIZE 권한만 줍니다. 서비스가 재시작되어도 **기존 에이전트를 종료하지 않고 넘겨받습니다**.
  - 넘겨받는 방법: 서비스가 시작할 때 이미지 경로가 에이전트 exe인 프로세스를 세션별로 찾아 `OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)`로 연결합니다.
- 에이전트를 실행한 직후 프로세스 보안 설명자를 바꿉니다.
  - 소유자를 SYSTEM으로 바꿉니다.
  - DACL은 SYSTEM 모든 권한, 사용자는 `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`만 허용합니다.
  - 이렇게 하면 표준 사용자는 작업 관리자로 에이전트를 끝낼 수 없습니다.
  - `SetSecurityInfo(SE_KERNEL_OBJECT, OWNER | DACL)`을 쓰고, 실패하면 로그만 남깁니다.
- 종료 감지는 5초 틱이 아니라 `ThreadPool.RegisterWaitForSingleObject`(프로세스 핸들)로 하고, 즉시 재실행합니다. 같은 세션에서 60초 안에 5번 넘게 실패하면 30초 백오프하고 status에 기록합니다.
- 다음 시점에 즉시 `Reconcile()`을 호출합니다: `OnSessionChange`(Logon, SessionUnlock, ConsoleConnect, RemoteConnect).

**에이전트 (`src/WindowAgent/Program.cs`)**

> **창 판정, 승인 목록, PIN 창 요청 부분은 `DESIGN-app-lock-redesign.md`로 대체됨.** 에이전트는 `enforcement.txt` v2의 `A:`(잠긴 앱)와 `U:`(해제된 앱) 줄만 보고 창을 앱 단위로 판정합니다. 아래 항목 중 승인 PID(`G:`)와 `W/F/L` 줄 언급은 이력입니다.

- 정책 원천은 `Runtime\enforcement.txt` 하나입니다. 소유자가 SYSTEM인지 검증합니다. 파이프 경로는 삭제합니다.
  - `Global\WAP.EnforcementChanged`를 기다리다 신호가 오면 다시 읽습니다. 2초 주기로도 다시 읽습니다.
- 창 숨김 대상은 Mode=window 앱 전체와, Mode=launch 앱 가운데 `LockedAtUtc` 이전에 시작된 프로세스입니다. 승인된 PID는 제외합니다.
- `close` 지시가 있는 앱은 최상위 창에 `WM_CLOSE`를 한 번 보냅니다.
- **종료 경로를 둘로 나눕니다.**
  - `AgentStop` 이벤트(서비스가 정상 중지하거나 설치 제거할 때): 숨긴 창을 복원하지 않고 종료합니다. 복원은 저널을 통해 다음 에이전트가 판단합니다. 설치 제거 때는 §9.3 설치 제거 절차에 따라 먼저 정책을 비운 뒤 정지시킵니다.
  - 정책상 해제: 해당 창을 복원합니다.
  - 예외로 종료하는 경우: 복원하지 않습니다. 현재 `finally`에서 전부 복원하는 코드는 삭제합니다.
- 시작할 때 저널을 읽고, 현재 정책상 숨길 대상이 아닌 항목만 복원합니다.
- 로그는 `%LOCALAPPDATA%\WindowsAppProtector.WinUI\Logs\agent.log`에 씁니다. 다음을 기록합니다.
  - 정책 적용
  - 숨김/복원 개수(1분 단위 요약)
  - 예외
- 반환 코드: 0=정지 이벤트, 2=중복 실행, 3=정책 파일 없음 30초 초과, 1=예외. 서비스는 이 코드를 로그에 남깁니다.

### 7.4 enforcement.txt 형식

> **→ `DESIGN-app-lock-redesign.md` §6.1(`WAP-ENF 2`)로 대체됨.** 아래 v1 형식은 더 이상 읽히지 않습니다(헤더가 다르면 에이전트는 이전 상태를 유지합니다).

```
WAP-ENF 1
rev=<policy revision>
W:<base64 path>                 # 창 숨김: 일반 exe 경로 전체 매칭
F:<base64 package family>       # 창 숨김: 패키지
L:<base64 path>|<lockedAtUtc ticks>   # launch 모드 앱: 이 시각 이전 프로세스의 창 숨김
C:<base64 path or family>       # 잠금 전환 시 WM_CLOSE 대상(한 번만, rev 기준)
G:<pid>|<startTimeUtc ticks>    # 승인됨: 숨기지 않음
```

---

## 8. 진단

### 8.1 로그 (`WapLog`)

- 형식은 한 줄에 한 이벤트입니다: `2026-11-23T14:03:12.481+09:00 INFO  service  rule.applied app=kakaotalk.exe mode=blocked`
  - 필드: 수준(5칸), 구성요소, 이벤트 키, `key=value`
  - 값에 공백이 있으면 큰따옴표로 감쌉니다.
- 인코딩은 **UTF-8(BOM 없음)**입니다. 예외는 `ex.GetType().Name`, `NativeErrorCode`/`HResult`, `Message` 순서로 기록합니다.
- 회전: 1MB를 넘으면 `.1`~`.3`으로 돌립니다.
- 위치:
  - 서비스와 UI: `ProgramData\...\Logs\{service,ui}.log`
  - Gate와 에이전트: §6.4, §7.3의 사용자 로컬 경로
- 기존 `service.log`, `protection.log`, `winui-crash.log` 작성 코드는 모두 `WapLog`로 바꿉니다. 크래시 로그는 `ui.log`에 `FATAL` 수준으로 남깁니다.
- 이벤트 로그(`EventLog.WriteEntry`)에는 서비스 시작·중지와 FATAL만 남깁니다.
- **한글이 깨지는 원인**: `build_setup.ps1`의 서비스와 에이전트 csc 호출에 `/codepage:65001`이 없습니다(Gate에는 있음). 모든 csc 호출에 추가하세요.

### 8.2 status.json (관리자가 아니어도 읽기 가능)

```
{ "SchemaVersion":1, "ServiceVersion":"…", "StartedAtUtc":"…", "UpdatedAtUtc":"…",
  "AppliedRevision":12, "PolicyError":null, "Healthy":true, "Watcher":"wmi|polling",
  "Apps":[{"Id":"…","Name":"카카오톡","Mode":"launch","Rule":"applied-gate","LastBlockedUtc":"…"}],
  "Agents":[{"Session":1,"State":"running|restarting|failed","Restarts":0}],
  "TamperEvents":[{"AtUtc":"…","Detail":"IFEO key removed: kakaotalk.exe"}] }
```

경로나 PIN 정보는 넣지 않습니다. 앱 이름만 넣습니다.

### 8.3 진단 스크립트

`.scratch/diag.ps1`을 `tools/diag.ps1`로 옮겨 다시 작성합니다.

- 관리자 권한 없이 `status.json`, `Logs\*.log`의 마지막 200줄, 사용자 로컬 Gate/에이전트 로그, 관리 IFEO 키 목록(HKLM 읽기는 일반 권한으로 가능), 서비스 상태를 `diag-output.txt` 하나로 모읍니다.
- 관리자 권한이 필요한 항목이 있으면 시도만 하고 실패를 기록합니다.

---

## 9. 일괄 변경 목록

아래는 최종 상태 기준으로 파일별로 정리한 변경 목록입니다. **순서나 중간 단계는 없습니다.** 모든 변경을 한 번에 반영한 뒤 마지막에 한 번 빌드합니다. 중간 상태를 빌드 가능하게 유지하거나, 옛 경로와 새 경로를 함께 두는 임시 코드를 만들지 마세요. 파이프와 새 채널이 공존하는 기간은 없습니다.

### 9.1 새로 만들 파일

| 파일 | 내용 |
|---|---|
| `src/Shared/WapPaths.cs`, `WapLog.cs`, `PolicyModel.cs`, `PolicyStore.cs`, `PolicyRules.cs`, `PinHash.cs`, `GateSpool.cs`, `StatusModel.cs`, `EnforcementFile.cs` | §4 |
| `src/Shared/LegacyMigration.cs` | §9.4 |
| `src/Service/ServiceHost.cs`, `ProtectionWorker.cs`, `SecureLayout.cs`, `PolicyHost.cs`, `RuleEngine.cs`, `ProcessWatcher.cs`, `GrantTable.cs`, `GateSpoolServer.cs`, `AgentSupervisor.cs`, `SessionLauncher.cs`, `StatusWriter.cs` | §5~§8 |
| `src/Avalonia/Services/UiSettingsStore.cs` | `ui.json` 읽기와 쓰기(System.Text.Json) |
| `src/Avalonia/Services/PolicyChangeNotifier.cs` | `PolicyChanged` 이벤트 신호 + `AppliedRevision` 대기(최대 3초) |
| `src/Avalonia/Services/ServiceStatusReader.cs` | `status.json` 읽기, 2초 주기 갱신 |
| `src/Avalonia/Services/FileFingerprint.cs` | `FileSize`와 SHA-256 계산(백그라운드, 64MB 초과는 생략) |
| `docs/THREAT-MODEL.md` | §2의 표와 보장 목록 |
| `docs/qa/2.0.0-backend.md` | §10의 수동 검증 절차서 |
| `tools/diag.ps1` | §8.3 |

### 9.2 삭제할 파일과 코드

- `src/Service/WindowsAppProtector.Service.cs`: 내용은 §9.1의 서비스 파일들로 옮기고 이 파일은 삭제합니다.
- `src/Service/LaunchAuthorizationServer.cs`: 삭제합니다.
- `src/Service/SessionAgentSupervisor.cs`: 삭제합니다. `AgentSupervisor`로 대체됩니다.
- `src/LaunchGate/GateProtocol.cs`: 삭제합니다. 필요한 상수는 `GateSpool.cs`로 옮깁니다.
- `src/Avalonia/Services/JsonSettingsStore.cs`, `ISettingsStore.cs`, `PinHasher.cs`: 삭제합니다.
- `src/Avalonia/Platform/WindowGuardService.cs`, `src/Avalonia/Services/ProtectedAppProcessService.cs`: 삭제합니다.
- `ProtectionService`: `RequestPolicyResyncAsync`, `StopProtectedProcessesAsync`, `WindowOnlyExecutableNames`, `GetBlockRuleName`, `UsesWindowOnlyBlocking`을 삭제합니다. 서비스 상태 조회와 재시작만 남깁니다.
- `src/Avalonia/Models/AppConfig.cs`, `ProtectedApp.cs`: 삭제하고 Shared의 `PolicyDocument`, `AppPolicy`, `UiSettings`로 대체합니다. ViewModel에서는 `Enabled`를 `Locked`로 바꿉니다.
- `MainWindow.axaml.cs`, `MainViewModel.cs`: `WindowGuardService`, `CloseRunningAppsAsync`, 재동기화 호출부와 관련 이벤트 핸들러를 삭제합니다.
- `.scratch/diag.ps1`: `tools/diag.ps1`로 대체합니다. `.scratch`는 커밋 대상이 아니므로 손대지 않습니다.

### 9.3 수정할 파일

**`build_setup.ps1`**
- 모든 csc 호출에 `/codepage:65001`을 붙입니다.
- 서비스, Gate, 에이전트, Setup 컴파일에 필요한 `src/Shared/*.cs`를 넣습니다.
- 서비스에는 `/reference:System.Management.dll`과 `/reference:System.Runtime.Serialization.dll`을 넣습니다. Gate와 에이전트에도 `System.Runtime.Serialization.dll`을 넣습니다.
- 서비스 소스 목록을 §9.1의 새 파일들로 바꿉니다.

**`src/Avalonia/WindowsAppProtector.App.csproj`**
- `GateProtocol.cs` 링크를 지우고 `src/Shared/*.cs` 링크를 추가합니다. 이 파일들에 한해 nullable 경고를 억제합니다.

**`src/LaunchGate/Program.cs`, `GateForm.cs`**
- `Exchange`를 스풀 클라이언트로 바꿉니다(§6). 응답이 없을 때 표시할 문구를 추가합니다.
- `--notice-blocked`를 추가하고, `gate.log`에 기록합니다.

**`src/WindowAgent/Program.cs`**
- §7.3과 §7.4대로 다시 작성합니다. 세대 GUID 인자는 삭제합니다.

**UI ViewModel과 View**
- `MainViewModel`:
  - 저장 경로를 `PolicyStore`, `UiSettingsStore`, `PolicyChangeNotifier`로 바꿉니다.
  - Locked가 false에서 true로 바뀔 때 `LockedAtUtc`를 기록합니다.
  - 앱을 추가하거나 경로가 바뀌면 `FileFingerprint`를 호출합니다.
  - 반영 확인에 실패하면 알림을 띄웁니다: "보호 서비스가 아직 변경 사항을 적용하지 않았습니다. 서비스 상태를 확인하세요."
- `AppDetailViewModel`과 `AppDetailPane`:
  - 앱별 PIN은 `secrets.json`의 `AppPins[Id]`로 읽고 씁니다.
  - `Rule=conflict`이면 다음 경고를 표시합니다: "다른 프로그램이 이 앱의 실행 설정을 사용하고 있어 잠글 수 없습니다."
- `SettingsViewModel`과 `SettingsPage`:
  - "보호 상태" 카드를 추가합니다(서비스, 적용된 버전, 에이전트, 최근 변조 감지).
  - 스타일은 `docs/DESIGN-ui-overhaul.md`의 토큰을 씁니다.
- `App.axaml.cs`:
  - `WriteProtectionLog`와 크래시 로그를 `WapLog`(구성요소 `ui`)로 바꿉니다.
- 유휴 잠금은 UI에 그대로 두고, 결과만 새 저장 경로로 보냅니다.

**`src/Installer/Setup.cs`**
- 업데이트 설치:
  - 서비스만 중지한 상태(에이전트는 실행 중)에서 파일을 교체하고 서비스를 시작합니다.
  - 새 서비스는 세대 GUID 인자 형식의 이전 에이전트를 찾아 종료한 뒤 새 에이전트를 띄웁니다. 이전 에이전트가 종료하면서 창을 복원하는 것은 허용합니다.
- 설치 제거 절차는 아래 순서를 지켜야 합니다.
  1. 모든 앱의 Locked를 false로 바꾸고 revision을 올립니다.
  2. 신호를 보내고 `AppliedRevision`을 최대 5초 기다립니다.
  3. `AgentStop`을 보냅니다.
  4. 서비스를 중지하고 삭제합니다.
  5. 기존 IFEO 정리 스크립트를 실행합니다.
  6. 데이터 폴더를 삭제합니다.
- `config.json` 경로 참조는 `WapPaths`로 바꿉니다.

**문서**
- `docs/BACKEND-REDESIGN-CONTEXT.md` 맨 위에 "이 문서의 결정은 DESIGN-backend-redesign.md로 대체됨"을 한 줄 추가합니다.
- `docs/DESIGN-rename-bypass.md` 맨 위에 "DESIGN-backend-redesign.md §7.1로 구현됨"을 표시합니다.
- README의 보안 절에 `docs/THREAT-MODEL.md` 링크를 추가합니다.

### 9.4 레거시 마이그레이션 (`LegacyMigration.Run()`)

서비스와 UI가 같은 코드를 호출합니다. 어느 쪽이 먼저 실행해도 결과가 같아야 하며, `Global\WAP.PolicyWrite` 뮤텍스 안에서 실행합니다.

**실행 조건**: `config.json`이 있고 `policy.json`이 없을 때만 실행합니다.

**변환**
- `Enabled`를 `Locked`로 옮깁니다.
- 앱마다 `Id`를 새로 만들고, `LockedAtUtc`에는 마이그레이션 시각을 넣습니다.
- 전역 PIN과 앱별 PIN은 `secrets.json`으로 옮깁니다.
- UI 전용 필드(`CloseToBackground`, `StartWithWindows`, `UpdateChannel`, `IdleLockMinutes`, `UnlockMinutes`, `UnlockUntil`, `GlobalHotkeys`)는 `ui.json`으로 옮깁니다.
- `FileSize`와 `Sha256`은 비워 둡니다. UI가 다음에 실행될 때 채우고, 그 전까지 서비스는 경로로만 판정합니다.
- 공유 `config.json`에 PIN이 없으면 사용자 프로필의 `config.json`과 `pin.json`에서 가져옵니다(현행 `JsonSettingsStore.LoadAsync` 규칙).

**정리**
- 원본 `config.json`은 `config.json.v2.bak`(SYSTEM과 Administrators만 접근)으로 이름을 바꿉니다.
- 사용자 프로필의 `config.json`과 `%LOCALAPPDATA%\WindowsAppProtector.WinUI\pin.json`은 삭제합니다. pin.json은 일반 사용자 권한으로 읽을 수 있는 PIN 해시 사본입니다.
- 사용자 프로필 경로는 UI 쪽에서만 정리합니다. 서비스는 사용자 프로필을 건드리지 않습니다.

---

## 10. 완료 체크리스트

빌드와 정적 검사는 구현 AI가 직접 확인합니다. 아래 수동 검증 항목은 관리자 셸이 필요하므로, 사용자가 `tools/diag.ps1`과 함께 실행할 수 있는 절차서 `docs/qa/2.0.0-backend.md`로 작성해 제출합니다.

**빌드와 정적 검사**
- [ ] `build_setup.ps1`가 경고 없이 성공(csc). UI `dotnet build -c Release` 성공.
- [ ] 저장소 전체에서 `NamedPipe`, `PipeName`, `ConnectToService`, `window-policy.txt`, `settings-write.lock`이 검색되지 않음.
- [ ] `WindowOnlyExecutableNames`, PBKDF2 구현, 데이터 경로 문자열이 `src/Shared` 밖에 없음.
- [ ] Shared 파일에 C# 6 이상의 문법이 없음(csc 빌드 통과로 확인).

**수동 검증 (절차서에 포함)**
1. 카카오톡 잠금, 차단 모드: 실행하면 차단 안내가 나오고 status에 `applied-blocked`가 기록된다.
2. Gate 모드: 실행하면 PIN 창이 나오고, 맞는 PIN이면 실행되며, 틀린 PIN을 5회 입력하면 대기 시간이 적용된다. **이전에 파이프 때문에 동작하지 않던 경로입니다.**
3. 잠금을 저장한 뒤 1초 안에 IFEO 키가 생성되고 status의 `AppliedRevision`이 갱신된다.
4. 보호 대상 exe를 `%TEMP%\x.exe`로 복사해서 실행하면 즉시 종료되고 안내가 표시된다.
5. Chrome 잠금: 창이 숨겨지고, 해제하면 복원된다. UI를 종료한 상태에서도 같다.
6. 표준 사용자가 작업 관리자로 에이전트를 끝내려 하면 거부된다. 관리자가 종료하면 1초 안에 다시 실행되고 창은 숨겨진 채로 유지된다.
7. 서비스를 재시작해도 숨긴 창이 깜빡이며 나타나지 않는다(에이전트 넘겨받기).
8. 관리자가 IFEO 키를 지우면 1초 안에 다시 생성되고 status의 `TamperEvents`에 기록된다.
9. 다른 프로그램의 IFEO 키가 있는 앱은 UI에 충돌 경고가 표시된다.
10. 2.0.0-beta.13 설치 위에 업데이트하면 기존 앱 목록, PIN, 잠금 상태가 유지되고, `config.json.v2.bak`이 생성되며, `pin.json`이 삭제된다.
11. 설치 제거 후 IFEO 관리 키, 서비스, 데이터 폴더가 남지 않고, 숨겨졌던 창이 모두 복원된다.
12. 모든 로그에 한글이 깨지지 않는다.

---

## 11. 확정된 결정

| 항목 | 결정 | 버린 대안과 이유 |
|---|---|---|
| P1 파이프 근본 원인 | **규명하지 않고 파이프를 폐기** | SYSTEM 컨텍스트 재현이 막혀 있음. 서비스가 만든 이벤트 객체와 ACL 파일은 동작이 확인됨 |
| IPC | 파일 스풀 + 커널 이벤트 | ALPC/RPC: C# 5로 구현하기 부담이 크고 P1과 같은 원인에 걸릴 위험. 레지스트리 큐: ACL 모델이 파일보다 복잡 |
| IFEO를 쓰는 주체 | 서비스 단독. UI는 레지스트리를 쓰지 않음 | UI 직접 적용: 두 프로세스가 쓰면 경합이 생기고 로직이 중복됨 |
| 프로세스 감시 | WMI `Win32_ProcessStartTrace` + 1초 스냅샷 | ETW 직접 소비: C# 5에서 P/Invoke 구현 비용이 큼. 미니필터: 서명과 배포 부담 |
| 우회 판정 | 경로가 같거나, 크기와 SHA-256이 같음 | 서명자 매칭은 이번 범위에서 제외 |
| 창 단위 앱 | 숨김 유지 | 프로세스 일시 중지: 브라우저 상태가 손상되거나 중단될 위험 |
| 에이전트 보호 | 프로세스 DACL과 소유자를 SYSTEM으로 + 즉시 재실행 | 보호 프로세스(PPL): 서명이 필요해 불가 |
| 실패 시 동작 | fail-closed(§2) | — |
| PIN 해시 저장 | `secrets.json`, ACL 보호, PBKDF2 120000회 유지 | DPAPI 암호화: 위협 모델상 관리자는 방어 대상이 아니므로 이득 없음 |
| 직렬화 | `DataContractJsonSerializer`로 통일 | System.Text.Json은 .NET Framework 쪽에서 쓸 수 없음 |
| 기존 IFEO 키 구조 | 유지 | 설치 제거 스크립트와 기존 설치본의 호환성 |
| 일시 해제(`UnlockUntil`, `UnlockMinutes`) | 이번 범위에서 손대지 않음 | 현재 서비스가 사용하지 않는 필드. 마이그레이션 때 `ui.json`으로 옮기기만 함 |
| 유휴 잠금 | UI가 판단(현행 유지) | 에이전트가 판단하려면 사용자가 쓸 수 있는 신호 경로가 필요해짐 |
| 새 외부 패키지 | 없음 | — |
| 버전과 릴리스 | 이 작업에서 바꾸지 않음 | 릴리스는 사용자가 수동 검증한 뒤 별도로 진행 |
