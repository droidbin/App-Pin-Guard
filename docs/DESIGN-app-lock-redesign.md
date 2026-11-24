# 개별 앱 잠금 재설계 명세 (2.0.0 기준)

이 문서는 구현 AI가 다른 자료 없이 한 번에 구현할 수 있도록 쓴 명세입니다. 기존 구조는 `docs/DESIGN-backend-redesign.md`를 따르며, 이 문서와 겹치는 부분은 **이 문서가 우선**합니다.

- 대상 브랜치: `master`
- 언어 제약: `src/Shared`, `src/Service`, `src/LaunchGate`, `src/WindowAgent`는 C# 5 문법, .NET Framework입니다. 새 외부 패키지는 쓰지 않습니다.
- 버전과 릴리스는 이 작업에서 바꾸지 않습니다.

---

## 1. 배경: 지금 무엇이 잘못되는가

### 1.1 사용자 보고

1. PIN을 입력해 해제해도 앱 창이 다시 숨겨진다.
2. 일부 앱에는 잠금이 적용되지 않거나 동작이 일관되지 않는다.
3. 잠금 해제 후에도 잠긴 상태에서 뜬 창(PIN 입력창)이 닫히지 않고 남는다.
4. 잠금 해제 후 마우스 커서가 사라진다.

### 1.2 로그로 확인한 사실 (2026-11-24, `%LOCALAPPDATA%\WindowsAppProtector.WinUI\Logs`)

- **승인 PID가 사라졌다 나타난다.** `09:07:34 agent.granted count=1 first=28680|…` 직후 `09:07:38 agent.unlock.check pid=28680 granted=none`. `09:13`에는 승인 개수가 2→3→2→1로 흔들림. 승인이 사라지는 순간 창이 다시 숨겨지고 PIN 창이 또 뜬다.
- **같은 프로세스에 PIN 창이 반복해서 뜬다.** chrome PID 28680 하나에 `gate.unlock.requested`가 10회 이상. `09:04:56` 승인 직후 `09:04:59`에 또 요청이 생기고, 그 요청은 끝내 승인/거부 로그가 없다. 이것이 "해제 후에도 남아 있는 창"이다.
- **에이전트가 자주 다시 시작된다**(08:31, 08:53, 09:04, 09:07, 09:09). 에이전트가 들고 있던 "이미 PIN 창을 띄웠다" 상태와 쿨다운이 재시작마다 사라진다.
- **카카오톡(launch 모드)은 실행할 때마다 PIN을 다시 묻는다**(09:13:00, 09:13:09, 09:13:17). 이미 실행 중이어도 그렇다.

### 1.3 근본 원인

| # | 원인 | 결과 |
|---|---|---|
| R1 | 해제 단위가 **PID(+시작 시각)**. 크롬·삼성 인터넷·Electron 앱은 프로세스가 여러 개이고, 새 실행은 기존 프로세스로 넘겨진 뒤 바로 종료된다. 창을 가진 프로세스와 승인된 프로세스가 자주 다르다. | 해제했는데 숨겨짐 / 일부 앱 미적용 |
| R2 | 해제 상태가 **세 곳에 흩어져 있다**: 서비스 `GrantTable`(PID 목록, pending, approvals 세 종류), 에이전트 메모리(`granted`, `unlockPrompt`, `nextPrompt`), Gate. 2초 주기 파일 폴링으로 동기화한다. `GrantedProcesses()`는 매번 `IsRunning` 재검사로 목록을 깎고, `Prune`도 별도로 깎는다. | 승인 목록 흔들림 |
| R3 | **PIN 창 소유자가 없다.** 에이전트가 "새로 숨긴 창"마다 Gate를 띄우고, 중복 방지는 에이전트 메모리에만 있다. 해제되어도 이미 뜬 다른 PIN 창을 닫는 주체가 없다. | PIN 창 중복·잔류 |
| R4 | launch 모드와 window 모드가 **서로 다른 해제 경로**(`authorize`+`track` vs `authorize`+`unlock`)를 쓴다. launch 모드의 재사용은 `AllowedMinutes > 0`일 때만 되고, 그것도 `RelockOnExit`와 얽혀 있다. | 동작이 앱마다 다름 |
| R5 | 커서: 에이전트가 숨긴 창을 `ShowWindowAsync(SW_SHOWNA)`로 복원하고, Gate는 고정 900ms 후 `SendInput`으로 커서를 깨운다. 복원 시점과 맞지 않으면 커서가 숨은 상태로 남는다(가설, §8에서 확정). | 커서 사라짐 |

---

## 2. 목표

### 2.1 목표

- **해제 단위는 앱 하나**입니다. 개별 앱 해제로 PIN을 넣으면 **그 앱만** 해제되고, 그 앱의 모든 프로세스와 모든 창이 열립니다. 다른 잠긴 앱은 영향을 받지 않습니다.
- launch 모드(일반 exe)와 window 모드(브라우저, 패키지 앱)가 **같은 해제 상태**를 씁니다.
- 해제 상태의 원천은 **서비스 한 곳**입니다. 에이전트와 Gate는 읽기만 합니다.
- **PIN 창은 앱마다 사용자 세션당 하나**만 뜹니다. 그 앱이 해제되면 떠 있던 PIN 창은 스스로 닫힙니다.
- 에이전트나 Gate가 재시작되어도 해제 상태와 PIN 창 중복 방지가 유지됩니다.
- 잠금 해제 후 커서가 항상 보입니다.

### 2.2 비목표

- 전체 잠금 해제(UI에서 `Locked=false`로 바꾸는 것), 유휴 잠금, 잠금 시간대 계산 방식은 바꾸지 않습니다.
- IFEO 키 구조(`WindowsAppProtectorManaged`, `WAP.Launch.N`, `Gate.exe --launch/--blocked`)는 유지합니다.
- 이름 변경·복사 우회 판정(경로 또는 크기+SHA-256)은 유지합니다.
- UI 디자인 변경은 없습니다. (상태 표시 문구 하나만 §6.6)

### 2.3 반목표 (이렇게 되면 기능이 맞아도 실패)

- 한 앱을 해제했는데 다른 잠긴 앱의 창이 보이거나 실행된다.
- 해제된 앱의 창이 해제 기간 중에 한 번이라도 다시 숨겨진다.
- PIN 창이 같은 앱에 대해 동시에 두 개 이상 뜬다.
- 서비스가 응답하지 않을 때 앱이 열린다(fail-closed 유지).

---

## 3. 방식 결정

| 방식 | 내용 | 판단 |
|---|---|---|
| **A. 앱 단위 해제 상태 (채택)** | 서비스가 `(사용자 SID, 세션, AppId)`마다 해제 레코드 하나를 둔다. 감시기·에이전트·Gate는 "이 프로세스/창이 어느 앱인가 → 그 앱이 이 세션에서 해제됐나"만 판단한다. | R1~R4를 구조적으로 제거. 서비스·에이전트·Gate를 함께 바꿔야 해서 작업량이 큼 |
| B. 현 구조 패치 | 승인 목록 흔들림 수정, PIN 창 중복 방지, 자식 프로세스 승인 상속 | 작지만 PID 단위가 남아 다른 앱에서 같은 종류의 버그가 재발 |
| C. 브라우저도 실행 단계 차단 | window 모드를 없애고 IFEO로 전부 막기 | 크롬은 chrome.exe를 자식으로 계속 띄워 매번 걸리고, 이미 떠 있는 창은 막을 수 없음. 탈락 |

사용자 결정: "개별 앱 해제 기능으로 잠금을 해제한 경우에는 해당 앱만 해제되어야 함." → A.

---

## 4. 핵심 모델: 앱 해제 레코드

### 4.1 앱 판별 (모든 컴포넌트 공통)

프로세스가 어느 앱인지는 `src/Shared/PolicyRules.cs`에 새 함수 하나로 통일합니다. 서비스, 에이전트, Gate가 같은 함수를 씁니다.

```
AppMatcher.Match(policy 또는 enforcement 앱 목록, imagePath, packageFamily) → AppId 또는 null
```

판정 순서:

1. `packageFamily`가 있고 잠긴 패키지 앱의 `PackageFamilyName`과 같으면 그 앱.
2. `imagePath`가 잠긴 앱의 `Path`와 같으면(`PolicyRules.PathsEqual`) 그 앱.
3. (서비스에서만) launch 모드 앱에 대해 크기+SHA-256 일치(기존 `ProcessWatcher.MatchApp` 로직을 그대로 옮김).

에이전트에서 창 → 앱 판별:

- 창 소유 프로세스로 위 1~2를 적용합니다.
- 소유 프로세스가 `ApplicationFrameHost.exe`이면 자식 창의 프로세스 중 **패키지 패밀리가 있는 것**만으로 판정합니다. Win32 앱의 자식 창(크롬 GPU/렌더러 등)은 판정에 쓰지 않습니다. 현재 미커밋 변경(`MatchesWindow`의 `childInfo.Family != null`)이 이 규칙이며, 새 구조에서도 유지합니다.

### 4.2 레코드

서비스 메모리에 둡니다(`src/Service/UnlockTable.cs`, `GrantTable.cs`를 대체).

```
AppUnlock
  string  UserSid
  int     SessionId
  string  AppId
  long    PinVersion        // 해제에 쓴 PIN 레코드 버전. PIN이 바뀌면 무효
  string  Settings          // SettingsKey(app) — AllowedMinutes, 잠금 시간대, RelockOnExit. 바뀌면 무효
  DateTime UnlockedUtc
  DateTime? ExpiresUtc      // AllowedMinutes > 0 일 때 UnlockedUtc + AllowedMinutes
  bool    SeenRunning       // 해제 후 그 앱의 프로세스를 한 번이라도 본 적이 있는가
  DateTime LastSeenRunningUtc
```

키: `UserSid|SessionId|AppId`. 같은 키로 다시 해제하면 덮어씁니다.

### 4.3 해제가 끝나는 조건 (재잠금)

아래 중 하나라도 맞으면 레코드를 지우고 `enforcement.txt`를 다시 씁니다.

| 조건 | 규칙 |
|---|---|
| 앱 종료 | `SeenRunning == true`이고, 그 세션에서 그 앱의 프로세스가 **3초 연속** 하나도 없음. 단 `AllowedMinutes > 0`이고 `RelockOnExit == false`이면 이 조건을 적용하지 않음(시간이 남아 있으면 다시 실행해도 PIN을 묻지 않음) |
| 실행 실패 | `SeenRunning == false`인 채로 해제 후 **30초** 경과 |
| 허용 시간 만료 | `ExpiresUtc <= now` |
| 정책 변경 | 앱 삭제, `Locked=false`, PIN 버전 변경, `Settings` 변경 |
| 세션 종료 | 해당 세션 Logoff, 서비스가 `RevokeAll()`을 부르는 기존 시점(잠금 화면 등) |

- 3초 유예는 크롬·카카오톡처럼 런처가 기존 프로세스에 넘기고 끝나거나 업데이터가 재시작하는 경우를 위한 것입니다.
- **허용 시간 만료 시 앱이 실행 중이면**: window 모드 앱은 창이 다시 숨겨지고 PIN을 묻습니다. launch 모드 앱은 실행 중인 프로세스를 종료하지 않고, 창을 숨긴 뒤 PIN을 묻습니다(창 숨김은 기존 `L:` 규칙과 같은 메커니즘). *(구현자 판단 아님: 사용자 확인 필요 항목 §11-1)*
- 기존 `AllowedMinutes == 0`의 의미("실행할 때마다 PIN")는 **"앱을 닫을 때까지 해제"**로 바뀝니다. 실행 중인 앱을 다시 실행해도 PIN을 묻지 않습니다. 이것이 사용자 보고 1.2-④의 수정입니다.

### 4.4 서비스의 실행 중 판정

`ProcessWatcher`의 1초 스냅샷을 재사용합니다. 스냅샷마다 `(세션, AppId) → 실행 중 프로세스 수`를 계산해 `UnlockTable.Observe(snapshot, now)`에 넘깁니다. 이미지 경로·패키지 패밀리 조회 결과는 `(pid, startTicks)` 키로 캐시합니다(스냅샷마다 전체 조회 금지).

---

## 5. 흐름

### 5.1 launch 모드 (예: 카카오톡)

1. 사용자가 실행 → IFEO가 `Gate.exe --launch <path> [args]`를 띄움.
2. Gate → `authorize(path, pin="")`.
   - 서비스: 해제 레코드가 있으면 `Approved`. 없으면 `Prompt`.
3. `Prompt`이면 Gate가 **PIN 창 뮤텍스**(§5.4)를 잡고 PIN 창을 띄움. 뮤텍스를 못 잡으면(이미 그 앱 PIN 창이 있음) 그 창을 앞으로 가져오고 PIN 창 쪽 결과를 기다림(§5.4).
4. PIN 확인 → 서비스가 해제 레코드 생성 → `Approved`.
5. Gate가 앱을 `CreateProcess`로 실행하고 종료. **`track` 요청은 없앱니다.**
6. 감시기: 새 프로세스의 앱이 해제 상태이면 통과, 아니면 종료(기존 동작).

감시기의 허용 규칙은 다음 두 개만 남깁니다.

- 잠금 시간대가 아님
- `UnlockTable.IsUnlocked(sid, session, appId)`

기존의 PID 승인, 부모 PID 승인, "직전 승인 Gate의 자식" 규칙은 전부 삭제합니다. Gate는 레코드가 생긴 **뒤에** 앱을 띄우므로 경합이 없습니다.

### 5.2 window 모드 (예: 크롬, 삼성 인터넷, 패키지 앱)

1. 에이전트가 잠긴 앱의 보이는 창을 찾아 숨김(해제 레코드가 없을 때만).
2. 창을 새로 숨겼고 그 앱의 PIN 창이 없으면 `Gate.exe --unlock <AppId> "<exe 경로>"`를 띄움. **해제 대상은 PID가 아니라 AppId** (경로는 표시용, §6.5).
   - 에이전트 쪽 중복 방지: 앱마다 마지막으로 띄운 시각을 기억해 5초 안에는 다시 띄우지 않음. 진짜 중복 방지는 Gate 뮤텍스(§5.4)가 담당하므로 에이전트가 재시작되어도 안전.
   - 사용자가 PIN 창을 **취소**하면: 그 앱에 대해 "다음 새 창이 생길 때까지" 다시 띄우지 않음. 이 상태는 에이전트 메모리에만 두고, 재시작 시 사라져도 됨(최악의 경우 한 번 더 뜰 뿐).
3. Gate가 PIN을 받아 `unlock(appId, pin)` 요청 → 서비스가 PIN 확인 후 해제 레코드 생성 → `Approved`.
4. 서비스가 `enforcement.txt`를 다시 쓰고 `Global\WAP.EnforcementChanged`를 신호.
5. 에이전트가 즉시 다시 읽고, 해제된 앱의 숨긴 창을 모두 복원.
6. Gate는 **그 앱의 창이 실제로 보일 때까지** 최대 3초 기다린 뒤(§8), 커서 복구 후 종료.

패키지 앱은 지금 `CanUseWindowUnlock`이 거부해서 PIN으로 열 수 없습니다. 새 구조에서는 AppId 단위로 해제하므로 패키지 앱도 같은 흐름을 씁니다(`CanUseWindowUnlock`에서 `!app.IsPackaged` 조건 제거).

### 5.3 잠금 시점에 이미 실행 중이던 launch 모드 앱 (`L:` 규칙)

기존과 같이 `LockedAtUtc` 이전에 시작된 프로세스의 창을 숨깁니다. 달라지는 점: 숨긴 뒤 window 모드와 같이 `Gate.exe --unlock <AppId> "<exe 경로>"`로 PIN을 받을 수 있고, 해제되면 그 앱 전체가 열립니다.

### 5.4 PIN 창 단일화 (Gate)

- Gate는 PIN 창을 띄우기 전에 `Local\WAP.Prompt.<AppId>` 이름의 뮤텍스를 잡습니다(AppId는 GUID라 이름에 안전). 세션 로컬이므로 세션당 앱당 하나입니다.
- 못 잡으면: 이미 떠 있는 PIN 창을 찾아 앞으로 가져옵니다. 창은 `GateForm`이 만든 고유 클래스/제목(`WAP.Prompt.<AppId>`를 창 속성 `SetProp`으로 붙임)으로 찾습니다. 그다음:
  - `--unlock` 모드: 바로 종료(코드 0).
  - `--launch` 모드: 1초 간격으로 `authorize(path, "")`를 최대 120초 반복해 `Approved`가 되면 앱을 실행, 뮤텍스를 잡을 수 있게 되었는데(상대 창이 취소로 닫힘) 여전히 `Prompt`이면 종료.
- PIN 창이 떠 있는 동안 Gate는 500ms마다 `enforcement.txt`를 읽어, **그 앱이 이 세션에서 해제됐거나 더 이상 잠겨 있지 않으면 창을 스스로 닫습니다.** (다른 경로로 해제된 경우의 잔류 창 제거. 사용자 보고 3번.)
- `enforcement.txt` 읽기는 에이전트와 같은 소유자 검증(`WapSecurity.IsOwnedByServiceAccount`)을 거칩니다.

---

## 6. 변경 상세

### 6.1 `enforcement.txt` 형식 v2 (`src/Shared/EnforcementFile.cs`)

```
WAP-ENF 2
rev=<policy revision>
A:<appId>|<kind>|<base64 match>|<lockedAtUtc ticks 또는 0>
U:<sessionId>|<base64 userSid>|<appId>
C:<base64 path or family>
```

- `kind`: `W`(window 모드 Win32, match=경로), `P`(패키지, match=패밀리), `L`(launch 모드, match=경로, `lockedAt` 이전 프로세스만 숨김).
- `A:` 줄은 지금 잠금 시간대 안에 있는 잠긴 앱만 씁니다(기존 `W/F/L` 생성 규칙과 동일한 조건).
- `U:` 줄은 현재 유효한 해제 레코드 전부. 에이전트·Gate는 **자기 세션 ID와 자기 사용자 SID가 둘 다 같은 줄만** 봅니다.
- `G:`, `W:`, `F:`, `L:` 줄과 v1 파서는 삭제합니다. 헤더가 `WAP-ENF 2`가 아니면 `FormatException`.
- 직렬화 결과가 같으면 다시 쓰지 않는 기존 최적화는 유지합니다. 해제 레코드는 열고 닫을 때만 바뀌므로 파일은 드물게만 바뀝니다(R2 제거).

### 6.2 서비스

| 파일 | 변경 |
|---|---|
| `src/Service/UnlockTable.cs` (신규) | §4의 레코드와 규칙. `Authorize(policy, secrets, app, sid, session, pin, now, out retryAfter)`, `IsUnlocked(sid, session, appId)`, `Observe(runningBySessionApp, now)` → 바뀌었으면 true, `Prune(policy, secrets)`, `RevokeAll()`, `RevokeSession(session)`, `Snapshot()` → `U:` 줄용. 잠금 시도 제한(`Attempts\<sid>.json`, 5회 후 30초부터 지수 증가, 최대 900초)은 `GrantTable`에서 그대로 옮김 |
| `src/Service/GrantTable.cs` | 삭제 |
| `src/Service/GateSpoolServer.cs` | `authorize`: `UnlockTable.Authorize`. `unlock`: 요청 필드 `AppId`+`Pin`으로 받아 `UnlockTable.Authorize`와 같은 검증 후 레코드 생성(대상 PID 검증 삭제). `track`: 삭제(알 수 없는 op로 거부). 승인·거부·제한을 모두 `ServiceLog`에 `app=`, `session=`과 함께 기록 |
| `src/Service/ProcessWatcher.cs` | 허용 규칙을 §5.1의 두 개로 축소. 스냅샷마다 `(세션, AppId)` 실행 수를 계산해 `UnlockTable.Observe` 호출, true면 `policyHost.RequestApply()`. window 모드·패키지 앱도 실행 수 계산에 포함(종료는 하지 않음). 패키지 패밀리는 `GetPackageFamilyName`으로 조회(`NativeApi`에 추가) |
| `src/Service/PolicyHost.cs` | `WriteEnforcement`를 v2로. `Grants.GrantedProcesses()` 대신 `Unlocks.Snapshot()`. 정책 적용 시 `Unlocks.Prune` |
| `src/Service/ServiceHost.cs` | 세션 Logoff에 `RevokeSession`, 기존 `RevokeAll` 호출 지점 유지 |
| `src/Service/NativeApi.cs` | `GetPackageFamilyName(pid)` 추가 |

### 6.3 공유 코어

| 파일 | 변경 |
|---|---|
| `src/Shared/PolicyRules.cs` | `AppMatcher`(§4.1 1~2단계) 추가. `CanUseWindowUnlock`에서 패키지 앱 제외 조건 삭제. `SettingsKey` 이동(서비스·테스트 공용) |
| `src/Shared/EnforcementFile.cs` | v2 형식(§6.1). `EnforcementApp`(Id, Kind, Match, LockedAtTicks), `EnforcementUnlock`(Session, Sid, AppId) |
| `src/Shared/GateSpool.cs` | `GateRequest`에 `AppId` 필드 추가. `unlock` op는 `AppId`, `Pin` 사용. `track` op와 `Child` 필드 삭제 |

### 6.4 에이전트 (`src/WindowAgent/Program.cs`)

- 상태: `apps`(AppId → 판정 정보), `unlocked`(이 세션·사용자의 AppId 집합), 숨긴 창 저널(기존 유지).
- `ShouldHide(window)`: 창 → AppId(§4.1). AppId가 있고 `unlocked`에 없으면 숨김. `L` 종류는 프로세스 시작 시각 `< lockedAt`일 때만.
- 복원: 저널의 창 중 지금 숨길 대상이 아닌 것은 복원(기존 `RestoreWindows`와 같으나 판정만 교체).
- PIN 요청: `PromptUnlock(appId)` — §5.2-2 규칙. 인자는 `--unlock <AppId> "<exe 경로>"`.
- 삭제: `granted`, `hidePaths`, `hidePackages`, `hideBefore`, PID 기반 `PromptUnlock(uint pid)`, 디버그용 `agent.granted`/`agent.unlock.check` 로그(현재 미커밋 변경 포함).
- 로그 추가: `agent.unlock.prompt app=<name>`, `agent.restore app=<id> count=<n>`.
- 사용자 SID는 시작할 때 `WindowsIdentity.GetCurrent().User.Value`로 한 번 구합니다.

### 6.5 Gate (`src/LaunchGate/Program.cs`, `GateForm.cs`)

- `--unlock <AppId> "<exe 경로>"`: AppId가 GUID 형식이 아니면 종료 코드 1. 경로는 `GateForm`이 앱 이름과 아이콘을 표시하는 데만 씁니다(`GateForm(appPath)`는 지금도 경로에서 이름·아이콘을 얻음). 에이전트는 창 소유 프로세스의 이미지 경로를 넘기고, 패키지 앱이면 자식 창에서 찾은 앱 프로세스의 이미지 경로를 넘깁니다. 서비스 요청에는 AppId만 쓰고 경로는 보내지 않습니다.
- §5.4 뮤텍스, 기존 창 활성화, 해제 감지 시 자동 닫기.
- `--launch`: `track` 호출 삭제.
- 커서 처리: §8.

### 6.6 UI (`src/Avalonia`)

- `status.json`에 앱별 `UnlockedSessions`(해제된 세션 수) 추가, 앱 목록에서 잠긴 앱이 현재 해제 중이면 "잠금 해제됨(사용 중)"으로 표시. 그 외 UI 변경 없음.
- UI 코드가 `track`/PID 승인 개념을 참조하는 곳이 있으면 함께 정리.

---

## 7. 동기화와 경합 규칙

- 해제 레코드 생성·삭제는 `UnlockTable` 안의 단일 lock으로만 합니다.
- 서비스는 레코드가 바뀔 때마다 `enforcement.txt`를 쓰고 이벤트를 신호합니다. 에이전트는 신호 후 100ms 지연 없이 바로 읽습니다(현재 `Thread.Sleep(100)` 삭제. 파일은 원자적 교체로 쓰이므로 불필요).
- 에이전트의 2초 주기 재읽기는 백스톱으로 유지합니다.
- 에이전트는 `enforcement.txt`를 읽지 못하거나 형식이 틀리면 **직전 상태를 유지**합니다(지금과 같음). 처음부터 정책이 없으면 기존처럼 30초 후 종료 코드 3.

---

## 8. 커서 사라짐

### 8.1 먼저 재현하고 원인을 확정할 것

구현 전에 다음을 로그로 남기는 진단 빌드를 만들어 사용자 PC에서 재현합니다.

- Gate: PIN 창 닫힘 직후, 승인 직후, 창 복원 확인 직후 각각 `GetCursorInfo().flags`, `SPI_GETMOUSEVANISH`, 전경 창의 프로세스 이름.
- 사용자 확인 질문(구현 AI는 사용자에게 물어볼 것): 커서가 사라진 상태에서 **마우스를 움직이면 다시 보이는가?**
  - 보인다 → Windows "입력 중 포인터 숨기기"가 PIN 타이핑으로 걸려 있는 상태. 정상 동작에 가까우므로 §8.2만 적용.
  - 안 보인다 → 다른 원인. 진단 로그로 판단해 §8.2 위에 추가 조치.

### 8.2 기본 조치

- 고정 `Thread.Sleep(900)` 대신, Gate는 승인 후 **그 앱의 창이 보이는 상태가 될 때까지**(최대 3초, 100ms 간격 `EnumWindows` + §4.1 판정) 기다립니다.
- 창이 보이면 `AllowSetForegroundWindow`/`SetForegroundWindow`로 그 창을 앞으로 가져온 다음 `EnsureCursorVisible()`을 **한 번** 호출합니다.
- 에이전트의 복원 명령을 `SW_SHOWNA`(8)에서 `SW_SHOW`(5)로 바꿀지는 §8.1 결과로 정합니다. 기본값은 현행 유지.

---

## 9. 구현 순서 (일괄 구현용)

각 단계가 끝날 때마다 빌드가 통과해야 합니다. 빌드는 `build_app.bat`(앱), 서비스·Gate·에이전트는 기존 프로젝트 빌드를 그대로 씁니다.

1. **Shared**: `AppMatcher`, `EnforcementFile` v2, `GateSpool` 요청 필드 변경. `tests/UnitTests/SharedCoreTests.cs`에 v2 직렬화 왕복, `AppMatcher` 판정(경로, 패키지, 대소문자, ApplicationFrameHost 자식 규칙은 에이전트 쪽이므로 제외) 테스트 추가.
2. **Service**: `UnlockTable` 신규, `GrantTable` 삭제, `GateSpoolServer`·`ProcessWatcher`·`PolicyHost`·`ServiceHost` 연결. `UnlockTable` 단위 테스트: 해제 → 실행 관측 → 3초 무실행 후 재잠금, 30초 미실행 재잠금, 허용 시간 만료, `RelockOnExit=false`+`AllowedMinutes>0`에서 종료 후에도 유지, PIN 버전 변경 시 무효, 다른 세션·다른 앱은 영향 없음, 시도 제한.
3. **Agent**: §6.4. `tests/WindowAgentSmoke`를 v2 형식으로 갱신.
4. **Gate**: §5.4, §6.5, §8.2.
5. **UI**: §6.6.
6. **문서**: `docs/DESIGN-backend-redesign.md` §7.2, §7.3 에이전트 부분, §7.4에 "→ `DESIGN-app-lock-redesign.md`로 대체" 표시. `docs/qa/`에 §10 체크리스트를 `2.0.x-app-lock.md`로 추가.

미커밋 변경 처리: `src/LaunchGate/Program.cs`(900ms 대기)와 `src/WindowAgent/Program.cs`(진단 로그, 자식 창 판정)는 이 작업 안에서 대체·흡수합니다. `dist/` 아래 바이너리 변경, `.scratch/`, `tools/diag-output.txt`는 이 작업과 무관하므로 건드리거나 커밋하지 않습니다.

---

## 10. 완료 체크리스트 (실기 검증)

1. 크롬을 잠그고 실행 → PIN 창 **1개**만 뜸. PIN 입력 → 크롬의 모든 창이 보이고, 5분 동안 한 번도 다시 숨겨지지 않음.
2. 해제된 크롬에서 새 창(Ctrl+N), 새 실행(바탕화면 아이콘) → PIN 없이 열림.
3. 크롬을 모두 닫고 3초 뒤 다시 실행 → PIN을 다시 물음(`AllowedMinutes=0` 기준).
4. 크롬과 삼성 인터넷을 둘 다 잠그고 크롬만 해제 → 삼성 인터넷은 계속 숨겨짐.
5. 크롬 PIN 창이 떠 있는 상태에서 크롬 아이콘을 여러 번 클릭 → PIN 창은 계속 1개.
6. PIN 창 두 개가 생길 수 있는 상황(에이전트 강제 재시작 직후 등)에서도 해제 후 남는 PIN 창이 없음.
7. 카카오톡 잠금 → 실행 시 PIN, 실행 중 다시 실행 → PIN 없이 기존 창이 뜸. 완전히 종료 후 재실행 → PIN.
8. 카카오톡을 이름 바꿔 복사한 exe로 실행 → 종료되고 안내가 뜸(기존 우회 차단 유지).
9. 패키지 앱(예: 계산기) 잠금 → 창 숨김 후 PIN으로 열 수 있음.
10. `AllowedMinutes=1`, `RelockOnExit=false` → 해제 후 앱 종료·재실행해도 1분 안에는 PIN 없음. 1분이 지나면 창이 숨겨지고 PIN 요청.
11. PIN 5회 오류 → 제한 메시지, 제한 시간 동안 모든 PIN 창에서 거부.
12. 서비스 중지 상태에서 잠긴 앱 실행 → 열리지 않음(fail-closed).
13. 해제 직후 마우스를 움직이지 않아도 커서가 보임(§8.1 결과에 따라 판정 기준 조정).
14. `agent.log`, `gate.log`, `service.log`에 해제·재잠금·PIN 창 이벤트가 앱 이름과 함께 남음.

---

## 11. 사용자 확인이 필요한 항목

1. **허용 시간 만료 시 실행 중인 앱**: 이 문서는 "창을 숨기고 PIN을 다시 묻는다"로 정했습니다(§4.3). 기존에는 launch 모드 앱의 경우 만료가 새 실행에만 영향을 주었습니다. 기존 동작을 유지하려면 이 항목만 바꾸면 됩니다.
2. **`AllowedMinutes = 0`의 의미 변경**: "실행할 때마다 PIN" → "앱을 닫을 때까지 해제"(§4.3).
3. **커서**: §8.1의 질문(마우스를 움직이면 커서가 다시 보이는가).

## 12. 확정된 결정

| 항목 | 결정 | 버린 대안과 이유 |
|---|---|---|
| 해제 단위 | 앱(`사용자 SID, 세션, AppId`) | PID: 다중 프로세스 앱에서 깨짐(R1) |
| 해제 상태 원천 | 서비스 `UnlockTable` 하나 | 서비스+에이전트 분산: 흔들림(R2) |
| PIN 창 중복 방지 | Gate의 세션 로컬 이름 뮤텍스 `Local\WAP.Prompt.<AppId>` | 에이전트 메모리: 재시작 시 소실(R3) |
| 재잠금 기준 | 프로세스 3초 연속 없음 / 30초 미실행 / 허용 시간 / 정책 변경 / 세션 종료 | 즉시 재잠금: 런처 핸드오프·업데이터 재시작에서 오작동 |
| launch 모드 `track` | 삭제 | 레코드가 실행 전에 생기므로 불필요 |
| 패키지 앱 PIN 해제 | 허용 | AppId 단위라 PID 검증 문제가 없어짐 |
| 해제 정보 전달 | `enforcement.txt` v2의 `U:` 줄 | 별도 파일: 원자성·ACL 경로가 하나 더 생김 |
