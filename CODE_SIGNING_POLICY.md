# Code signing policy

**Status:** application to SignPath Foundation in preparation. Releases published so far are **not code signed**. The statement below applies to releases signed after the project is accepted.

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)

## Team roles

| Role | Member |
|---|---|
| Committers and reviewers | LEE HYEONGBIN ([@droidbin](https://github.com/droidbin)) |
| Approvers | LEE HYEONGBIN ([@droidbin](https://github.com/droidbin)) |

- Changes from anyone who is not a committer are accepted only through pull requests reviewed by a committer.
- Every signing request is approved manually by an approver.
- All team members use multi-factor authentication for GitHub and SignPath.

## What gets signed

Only binaries built from the source code of this repository by its automated GitHub Actions workflow: `Setup.exe` and the App PIN Guard executables it installs. Third-party components are not signed with this project's certificate.

## System changes

The installer requires administrator rights, lists the changes and asks for confirmation before making any of them. It removes an earlier version (keeping PINs, settings and the app list), registers an automatically starting Windows service, an uninstall entry and shortcuts. The program manages Image File Execution Options registry rules for the apps you choose to protect, and creates a startup task if you enable starting with Windows. Uninstalling from Windows Settings, or running `Uninstall.bat` in the install folder, removes them.

## Privacy

See the [privacy policy](PRIVACY.md).
