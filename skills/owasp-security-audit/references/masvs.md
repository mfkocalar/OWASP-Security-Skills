# OWASP MASVS — Mobile App Security

Load this reference for iOS, Android, or cross-platform mobile
reviews. Mobile threat models differ from web: the device is
untrusted, the user may be hostile, and the binary ships to the
attacker. MASVS codifies what to do about that.

**Source:** OWASP Mobile Application Security Verification Standard —
<https://mas.owasp.org/MASVS/>.

**Edition verification:** MASVS 2.1.0 confirmed current — GitHub release tag
`v2.1.0`, published 2024-01-18, added the MASVS-PRIVACY category.
Source: <https://mas.owasp.org/MASVS/> (also see
<https://github.com/OWASP/masvs/releases/tag/v2.1.0>). Retrieved 2026-07-22.
No newer tag found.

## Structure

MASVS organizes requirements into **8 control groups**. Since v2.0.0
the standard defines no verification levels of its own: OWASP moved
them to the MAS Testing Profiles (<https://mas.owasp.org/Profiles/>),
namely the security profiles MAS-L1 (Essential Security), MAS-L2
(Advanced Security) and MAS-R (Resilient Security), and the privacy
profile MAS-P (Baseline Privacy). The Baseline, Hardened and High-assurance
tier subheadings in the group sections below are this skill's own
review-depth checklist. They are not MASVS levels, and not MAS Testing
Profiles such as MAS-L1, MAS-L2 or MAS-P.

| Code         | Group             | Focus                                    |
| ------------ | ----------------- | ---------------------------------------- |
| MASVS-STORAGE | Storage          | Data at rest, backups, IPC leakage       |
| MASVS-CRYPTO  | Cryptography     | Key management, algorithms, RNG          |
| MASVS-AUTH    | Authentication   | Biometrics, session, step-up             |
| MASVS-NETWORK | Network          | TLS, pinning, cleartext                  |
| MASVS-PLATFORM| Platform         | IPC, WebView, deep links                 |
| MASVS-CODE    | Code quality     | Dependency mgmt, memory safety           |
| MASVS-RESILIENCE | Resilience    | Anti-tamper, anti-debug (R-series)       |
| MASVS-PRIVACY | Privacy          | PII handling, consent                    |

## Related: MASWE

MASVS controls are abstract by design. OWASP's companion project
**MASWE** (Mobile Application Security Weakness Enumeration) is the
layer between the standard and the tests: MASVS ➡ MASWE ➡ MASTG. A
MASVS control states what must hold, a MASWE weakness is the
platform-agnostic flaw that indicates the control failed, and a MASTG
test (<https://mas.owasp.org/MASTG/>) is the platform-specific check
that detects it. MASTG does not yet have a dedicated test for every
weakness. MASWE is a separate project with its own versioning, not a
new edition of MASVS.

**Edition verification:** MASWE v1.0.0 — the first stable release,
GitHub release tag `v1.0.0`, published 2026-08-17 — defines 78
weaknesses (`MASWE-0001` to `MASWE-0078`) across the same 8 MASVS
groups. Source: <https://mas.owasp.org/MASWE/> (also see
<https://github.com/OWASP/maswe/releases/tag/v1.0.0>). Retrieved 2026-11-09.
IDs were renumbered once at v1.0.0 and are stable from there on;
beta-era IDs no longer apply.

To migrate a legacy reference, OWASP maps every beta-era ID to its
v1.0.0 weakness in the release's `OWASP_MASWE.yaml` asset.

| MASWE ID   | Title                                                | MASVS group   |
| ---------- | ---------------------------------------------------- | ------------- |
| MASWE-0001 | Sensitive Data Stored Unencrypted in Private Storage | MASVS-STORAGE |
| MASWE-0026 | Network Traffic Not Encrypted                        | MASVS-NETWORK |

## How to apply

When reviewing a mobile app, pick the categories triggered by what
you see. Biometric unlock → MASVS-AUTH. Keychain / Keystore →
MASVS-STORAGE + MASVS-CRYPTO. Network client → MASVS-NETWORK. Custom
URL scheme → MASVS-PLATFORM. Finance / health app → add
MASVS-RESILIENCE.

---

## MASVS-STORAGE — Data at Rest

**Baseline**
- No sensitive credentials in plaintext.
- Sensitive data excluded from device backups.
- Use platform credential storage APIs (Keychain on iOS, EncryptedSharedPreferences
  or Android Keystore on Android).

**Hardened**
- Sensitive data never written to shared filesystem locations
  (external storage, world-readable directories).
- Clipboard contents that contain credentials cleared after use.
- No sensitive data in crash logs, analytics payloads, or debug
  output.

**iOS secure storage**
```swift
import Security

func store(account: String, secret: Data) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecValueData as String: secret,
        kSecAttrAccessible as String:
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]
    SecItemDelete(query as CFDictionary)
    SecItemAdd(query as CFDictionary, nil)
}
```
- Pick the strictest `kSecAttrAccessible` value the feature allows.
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` blocks backup
  restore and off-device extraction.

**Android secure storage**
```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

val key = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
val prefs = EncryptedSharedPreferences.create(
    "secret_prefs", key, context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
)
prefs.edit().putString("api_token", token).apply()
```
- Exclude from auto-backup via `android:allowBackup="false"` or
  `android:fullBackupContent` XML rules.

**Checklist**
- [ ] No plaintext credentials on disk.
- [ ] Backup exclusion configured (iOS: `isExcludedFromBackup`;
      Android: `allowBackup="false"` or explicit rules).
- [ ] Platform credential APIs used for tokens.
- [ ] No sensitive data in logs, crash dumps, or analytics.

---

## MASVS-CRYPTO — Cryptography

**Baseline**
- No hardcoded keys.
- AES-256 for symmetric encryption; SHA-256 or better for hashing.
- Cryptographically secure RNG (`SecRandomCopyBytes` on iOS,
  `SecureRandom` on Android).

**Hardened**
- Keys derived with PBKDF2 / Argon2 when password-based.
- Authenticated encryption mode (GCM, CCM) — never raw CBC without
  MAC.
- Keys protected by the hardware-backed keystore where available.

**High-assurance**
- Hardware Security Module / Secure Enclave binding.
- Key rotation schedule; cryptographic agility (algorithm swap
  without code changes).

**Detection signals**
- `MODE_ECB`, `AES/ECB/*` in Java; `kCCOptionECBMode` on iOS.
- Hash of password with a single SHA-256 round (missing KDF).
- Keys in resource files, `BuildConfig`, plist, or `.strings`.
- `Random()` / `Math.random()` used for token generation.

---

## MASVS-AUTH — Authentication

**Baseline**
- Credentials sent over TLS only (see MASVS-NETWORK).
- Biometric flows require a user-presence event, not a cached
  success.

**Hardened**
- Step-up authentication before sensitive operations (transfers,
  profile edits, unlock of stored secrets).
- Session binding to device; tokens invalidated on re-provisioning.

**iOS biometric with keychain-backed key**
```swift
import LocalAuthentication

let ctx = LAContext()
ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
    localizedReason: "Unlock vault") { success, error in
    guard success else { return }
    // Retrieve the key only after successful biometric:
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: "vault.key".data(using: .utf8)!,
        kSecUseAuthenticationContext as String: ctx,
        kSecReturnRef as String: true,
    ]
    // ...
}
```
- Bind the credential to the biometric context — don't gate on a
  boolean returned by the framework alone.

**Checklist**
- [ ] Biometric unlock binds to a keystore item, not a boolean.
- [ ] Sensitive actions require step-up.
- [ ] Tokens revoked on device change / OS upgrade / biometric
      enrollment change.

---

## MASVS-NETWORK — Transport Security

**Baseline**
- TLS 1.2+ on all network traffic; no cleartext HTTP.
- Accept only valid certificates; no `trustManager.checkServerTrusted`
  no-ops.

**Hardened**
- Certificate or public-key pinning for sensitive endpoints.

**High-assurance**
- Mutual TLS (mTLS) for privileged APIs.
- Automated monitoring for rogue CA issuance (CT log watching).

**Android Network Security Config (cleartext off + pinning)**
```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set>
      <pin digest="SHA-256">+MIIBIjAN...</pin>
    </pin-set>
  </domain-config>
</network-security-config>
```
- Ship at least two pins (current + next) to avoid bricking the app
  on rotation.

**iOS App Transport Security** — ATS enforces TLS by default; every
`NSAllowsArbitraryLoads: true` in Info.plist is a finding unless
justified.

**Checklist**
- [ ] No cleartext HTTP endpoints in production manifests.
- [ ] Custom TrustManager implementations do real checks.
- [ ] Pinning in place for auth / PII-carrying endpoints.
- [ ] Two pins (current + next) configured.

---

## MASVS-PLATFORM — OS Integration

**Baseline**
- Deep-link / custom-URL handlers validate their input; no
  `startActivity` on arbitrary attacker-controlled intents.
- WebView: `setJavaScriptEnabled(false)` unless needed;
  `setAllowFileAccess(false)`; never load untrusted URLs.
- IPC: explicit intents only; exported components have permissions.

**Hardened**
- Android App Links / iOS Universal Links (signed association,
  not just custom scheme).
- Sensitive `Intent` filters guarded by signature-level permissions.

**Detection signals**
- `<intent-filter>` with `android:exported="true"` and no permission.
- iOS Info.plist `CFBundleURLTypes` with no associated-domain.
- `WebView` loading a URL derived from user input without domain
  check.
- `addJavascriptInterface` exposing privileged methods.

**Checklist**
- [ ] Exported components protected by permission or
      `android:exported="false"`.
- [ ] Deep links verified by App Links / Universal Links.
- [ ] WebView hardening: no file access, no JS unless needed, no
      untrusted origins.

---

## MASVS-CODE — Code & Dependency Hygiene

**Baseline**
- Target the latest stable SDK; keep dependencies current.
- No hardcoded secrets in the binary.

**Hardened**
- OTA update verification (signature + version pinning).
- Release builds stripped of debug symbols and hidden logging.

**High-assurance**
- Obfuscation (R8 / ProGuard on Android, stripping on iOS) for code
  that contains defense-in-depth logic.

**Detection signals**
- `BuildConfig.DEBUG` branches that run in release builds.
- `applicationDebuggable="true"` in release manifests.
- Dependencies pinned to `+` or missing lockfiles.

**Checklist**
- [ ] Release builds have `debuggable` off, symbols stripped.
- [ ] No secrets in resource files, string tables, or `BuildConfig`.
- [ ] Dependency audit in CI; criticals block release.

---

## MASVS-RESILIENCE — Anti-Tamper (MAS-R)

Relevant for high-value apps (finance, DRM, enterprise MDM). Lower
tiers may skip.

**Controls**
- Root / jailbreak detection with graceful degradation, not crash.
- Anti-debug / anti-hook (ptrace, mach exceptions).
- Integrity checks of the app binary and resources.
- Environment checks (emulator detection, Frida/Objection
  signatures).

**Android root-detection sketch**
```kotlin
fun isRooted(): Boolean {
    if (File("/data/adb/magisk").exists()) return true
    val which = try {
        ProcessBuilder("which", "su").redirectErrorStream(true)
            .start().waitFor()
    } catch (_: Exception) { -1 }
    return which == 0
}
```
- Treat resilience as defense-in-depth, not primary security. A
  determined attacker on their own device will win; the goal is cost,
  not prevention.

**Checklist**
- [ ] App detects a modified environment and degrades features.
- [ ] Binary integrity check on startup.
- [ ] No critical authorization decisions made by the client alone.

---

## MASVS-PRIVACY — Privacy

**Baseline**
- Only collect data the app needs.
- Privacy policy linked in-app and in store listing.

**Hardened**
- In-context permission rationale before prompting the OS dialog.
- User consent captured and revocable for optional data sharing.

**High-assurance**
- Privacy by design: data minimization, differential privacy, on-
  device processing where possible.

**Checklist**
- [ ] Permission prompts preceded by in-context explanation.
- [ ] No analytics SDK in the release build collecting PII without
      consent.
- [ ] User can revoke consent and delete their data from within the
      app.
