# Design

## Exact closed inventory

The existing Setting, Launcher and VehicleSetting owners remain unchanged. Add SettingNetwork (`com.qinggan.app.settingnewwork`), SystemUI (`com.qinggan.systemui`), BluetoothPhone (`com.qinggan.bluetoothphone`) and Media (`com.qinggan.media`). The SettingNetwork process spelling is an exact source identifier, not a normalized alias.

Each new slug `settingnetwork`, `systemui`, `bluetoothphone`, `media` has profiles `<slug>-a9` and `<slug>-a11`. A9 overlay packages are `ru.voboost.translation.<slug>`; A11 adds `.a11`. Owned files are `voboost-<slug>-ru.apk` and `voboost-<slug>-ru-a11.apk`, with the existing leading-dot staged suffix convention. Signed source artifact names remain `resource-i18n-ru-<profile>.apk`. Unknown or mismatched profile/package/target/file combinations remain rejected.

## Authority and scheduling

Seven explicit worker and observation slots retain independent endpoint, generation, document revision and current probe tickets. Each owner still admits at most its two exact candidates. The complete signed manifest/catalog inventory is checked before filtering to an owner; errors revoke all cached owners. Capability recognition does not expand the signed-declared owner set. Nonrunning owners remain waiting; no process is force-started. Setting remains the locale producer and picker owner, with its own readback admission independent from another owner's waiting or unsupported state. Full-scope readiness remains separate and incomplete until every signed-declared owner has current proof.

## Delivery boundary

The new tuples are source capabilities only until all four datasets and their Java implementations pass the separate batch review. Existing published metadata remains at three owners. This change does not modify product trust, APK admission, ledger formats or Java/Gradle publication.

## Cleanup boundary

Whole-collection admission and exact named paths remain bounded by the closed fourteen-profile enum. Preserve one native helper per collection pass, all unlinks before one resource-only reboot, all package/file/new-boot observations before any final receipt, and no-resource zero IO. Tests exercise thirteenth/fourteenth failure and interrupted replay. Existing journal/new-path SELinux proposals remain unapplied; host behavior is not Enforcing or device proof.
