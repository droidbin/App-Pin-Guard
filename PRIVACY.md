# Privacy policy

App PIN Guard has no account, analytics, advertising or telemetry. The developer does not operate a server for it and receives no data from it.

## Data stored on your PC

The protected app list, settings, salted PIN hashes and log files are stored locally under `%PROGRAMDATA%\Windows App Protector` and `%LOCALAPPDATA%`. They are not sent anywhere.

## Network connections

The only network connections are to GitHub, to update the program:

- **Update check:** after you first unlock the management window in a session, and when you press the update check button, the program requests the release list of this project from `api.github.com`.
- **Update download:** only when you choose to install an update, the program downloads `Setup.exe` from GitHub and verifies its SHA-256 digest.

These requests contain what any HTTPS request contains, such as your IP address and a program identifier (`User-Agent`). If you configure a GitHub token yourself, it is sent to GitHub with these requests. GitHub handles this data under the [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

## 개인정보 처리 (요약)

앱 목록·설정·PIN 해시·로그는 이 PC에만 저장됩니다. 외부 통신은 GitHub에서 업데이트를 확인하고, 사용자가 설치를 선택했을 때 내려받는 것이 전부입니다. 개발자에게 전송되는 데이터는 없습니다.
