# Threat Model — MSC Community Plugins (MSCP)

This document captures the results of an adversarial code review of the MSCP repository. It catalogs identified vulnerabilities (intentional or unintentional), attack surfaces, and recommendations organized by risk severity.

> **Review date:** March 2026
> **Scope:** All plugins, device drivers, shared SDK, build system, CI/CD workflows, and installer infrastructure.

---

## Table of Contents

1. [Attack Surface Overview](#1-attack-surface-overview)
2. [Critical Findings](#2-critical-findings)
3. [High Severity Findings](#3-high-severity-findings)
4. [Medium Severity Findings](#4-medium-severity-findings)
5. [Low / Informational Findings](#5-low--informational-findings)
6. [Build & CI/CD Pipeline Risks](#6-build--cicd-pipeline-risks)
7. [Positive Security Observations](#7-positive-security-observations)
8. [Recommendations Summary](#8-recommendations-summary)

---

## 1. Attack Surface Overview

| Component | Runs On | Network Exposure | Trust Boundary |
|-----------|---------|-----------------|----------------|
| **RTMP Device Driver** | Recording Server | Accepts inbound TCP (RTMP/RTMPS) from any IP | Untrusted network → server process |
| **RTSP Device Driver** | Recording Server | Outbound RTSP + RTP to configured cameras | Server → configured camera network |
| **HttpRequests Plugin** | Event Server | Outbound HTTP/HTTPS to admin-configured URLs | Server → arbitrary internet/intranet |
| **RTMPStreamer Plugin** | Event Server (background) + helper process | Outbound RTMP/RTMPS to streaming services | Server → streaming platforms |
| **Weather Plugin** | Smart Client (user workstation) | Outbound HTTPS to api.open-meteo.com | Workstation → public API |
| **RDP Plugin** | Smart Client (user workstation) | Outbound RDP to configured hosts | Workstation → target RDP hosts |
| **SmartBar Plugin** | Smart Client (user workstation) | None (local process execution) | User → local system |
| **SnapReport Plugin** | Smart Client (user workstation) | None (local file I/O) | User → local file system |
| **CertWatchdog Plugin** | Event Server | Outbound TLS probes to configured hosts | Server → monitored endpoints |
| **Auditor Plugin** | Event Server | None (Milestone API only) | Internal Milestone API |
| **Installer (MSI)** | Admin workstation | None | Installer → local file system |
| **CI/CD Workflows** | GitHub Actions runners | Outbound (NuGet, GitHub APIs) | CI runner → build infrastructure |

---

## 2. Critical Findings

### 2.1 Credential Exposure — RTMP Stream Keys Logged in Plaintext

| | |
|---|---|
| **Component** | RTMPStreamer Admin Plugin, RTMPStreamerHelper |
| **Files** | `Admin Plugins/RtmpStreamer/Background/RtmpStreamerBackgroundPlugin.cs`, `Admin Plugins/RtmpStreamer/RtmpStreamerHelper/Program.cs` |
| **Status** | ✅ **FIXED** |

**Description:** RTMP URLs contain stream keys (e.g., `rtmp://a.rtmp.youtube.com/live2/xxxx-xxxx-xxxx`) which are secrets. These were logged in full to application logs, system diagnostic logs, and the Milestone system log via `StreamConnected()`.

**Impact:** Stream keys exposed in logs could allow unauthorized streaming to the victim's channels (YouTube, Twitch, etc.) if logs are shared, captured, or stored insecurely.

**Fix applied:** A `MaskStreamKey()` helper now replaces the URL path with `***` in all log output, preserving the host for debugging while hiding the secret key.

---

### 2.2 Process Argument Injection via RTMP URL

| | |
|---|---|
| **Component** | RTMPStreamer Admin Plugin |
| **File** | `Admin Plugins/RtmpStreamer/Background/RtmpStreamerBackgroundPlugin.cs` |
| **Status** | ✅ **FIXED** |

**Description:** The RTMP URL from admin configuration was embedded directly into process arguments using simple quote-wrapping (`\"{rtmpUrl}\"`). A crafted RTMP URL containing double-quote characters could break out of the argument boundary and inject additional arguments to `RTMPStreamerHelper.exe`.

**Attack scenario:**
```
rtmpUrl = "rtmp://evil.com/live\" --malicious-arg \"x"
→ Arguments become: "..." "rtmp://evil.com/live" --malicious-arg "x" "..."
```

**Impact:** Arbitrary argument injection to the helper process. While the helper is a dedicated RTMP streaming tool (not a shell), injected arguments could alter its behavior.

**Fix applied:** An `EscapeArgument()` method now properly escapes backslashes and double-quotes per Windows process argument escaping rules before embedding in the argument string.

---

### 2.3 SSRF — HttpRequests Plugin Allows Requests to Internal Networks

| | |
|---|---|
| **Component** | HttpRequests Admin Plugin |
| **File** | `Admin Plugins/HttpRequests/Background/HttpRequestExecutor.cs` |
| **Status** | ✅ **FIXED** |

**Description:** The HTTP Requests plugin allows administrators to configure arbitrary HTTP requests triggered by Milestone events. No validation was performed on the destination address, allowing requests to:
- `http://localhost:*` — local services on the Event Server
- `http://169.254.169.254/` — cloud provider metadata endpoints (AWS/Azure/GCP)
- `http://192.168.x.x/`, `http://10.x.x.x/`, `http://172.16.x.x/` — internal network services

**Impact:** Server-Side Request Forgery (SSRF). An administrator (or attacker who gains admin access) could probe internal services, access cloud instance metadata (potentially retrieving IAM credentials), or interact with services behind the firewall.

**Fix applied:** A `CheckForSsrf()` method now resolves the target hostname and blocks requests to loopback (127.0.0.0/8, ::1), private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7), and link-local (169.254.0.0/16, fe80::/10) addresses.

---

### 2.4 Arbitrary Program Execution from SmartBar Config

| | |
|---|---|
| **Component** | SmartBar Smart Client Plugin |
| **Files** | `Smart Client Plugins/SmartBar/Client/SmartBarWindow.xaml.cs`, `Smart Client Plugins/SmartBar/SmartBarConfig.cs` |
| **Status** | ✅ **MITIGATED** |

**Description:** SmartBar reads program paths and arguments from `C:\ProgramData\Milestone\SmartBar\config.xml` and executes them via `Process.Start()`. The ProgramData directory may be writable by local users on some Windows configurations. Previously, `Process.Start(path)` without `UseShellExecute = false` was used, allowing shell interpretation of the path.

**Impact:** An attacker who can modify the config XML (e.g., local privilege escalation, shared workstation) could execute arbitrary programs with the Smart Client's privileges.

**Fix applied:** Process execution now uses `UseShellExecute = false` and validates that absolute paths point to existing files before execution. Bare executable names (resolved via PATH) are still allowed for convenience.

---

## 3. High Severity Findings

### 3.1 TLS Certificate Validation Bypass

| | |
|---|---|
| **Component** | HttpRequests Plugin, RTMPStreamer Plugin |
| **Files** | `Admin Plugins/HttpRequests/Background/HttpRequestExecutor.cs`, `Admin Plugins/RtmpStreamer/Rtmp/RtmpPublisher.cs` |
| **Status** | ✅ **PARTIALLY FIXED** (logging added) |

**Description:** Both plugins offer a configuration option to skip TLS certificate validation. When enabled, the callback `(sender, cert, chain, errors) => true` accepts any certificate, including self-signed, expired, or revoked certificates.

**Impact:** Man-in-the-middle attacks can intercept HTTPS traffic, potentially capturing credentials (Basic Auth passwords, Bearer tokens, stream keys).

**Fix applied:** A warning is now logged when certificate validation is disabled in the HttpRequests executor, creating an audit trail. The option remains available because some deployments use self-signed certificates for internal services.

**Remaining risk:** No UI warning is shown to the administrator when enabling this option.

---

### 3.2 Plaintext Credential Storage in Configuration

| | |
|---|---|
| **Component** | HttpRequests Admin Plugin |
| **Files** | `Admin Plugins/HttpRequests/Admin/HttpRequestUserControl.cs`, `Admin Plugins/HttpRequests/Background/HttpRequestsBackgroundPlugin.cs` |
| **Status** | ⚠️ **NOT FIXED** (architectural limitation) |

**Description:** HTTP authentication passwords (`AuthPassword`) and bearer tokens (`AuthToken`) are stored as plaintext strings in Milestone's configuration property storage. No encryption (e.g., Windows DPAPI) is applied.

**Impact:** Anyone with access to the Milestone configuration database or management API can read stored credentials in plaintext.

**Recommendation:** Encrypt credentials using `System.Security.Cryptography.ProtectedData` (DPAPI) before storing, and decrypt at use time. This is an architectural change requiring UI, storage, and background plugin modifications.

---

### 3.3 RTSP Credentials Embedded in URLs

| | |
|---|---|
| **Component** | RTSP Device Driver |
| **File** | `Device Drivers/Rtsp/RTSPDriver/DriverFramework/RTSPDriverConnectionManager.cs` |
| **Status** | ⚠️ **NOT FIXED** (design constraint) |

**Description:** The RTSP driver converts `SecureString` passwords to plaintext and embeds `username:password@host` directly into RTSP URLs passed to FFmpeg. The `SecureString` is immediately converted to a regular string, negating the benefit of the secure transport.

**Impact:** Credentials may persist in process memory and could be visible via process inspection or memory dumps.

**Recommendation:** Investigate whether FFmpeg's API supports passing credentials separately from the URL. Use memory pinning and zeroing for the plaintext password after use.

---

### 3.4 DLL Hijacking via Assembly Resolve Handler

| | |
|---|---|
| **Component** | RTMPStreamerHelper |
| **File** | `Admin Plugins/RtmpStreamer/RtmpStreamerHelper/Program.cs` |
| **Status** | ⚠️ **NOT FIXED** (acceptable risk) |

**Description:** The helper process registers an `AssemblyResolve` event handler that loads DLLs from multiple search directories using `Assembly.LoadFrom()`. While the directories are Milestone install directories (Program Files), the loading does not verify assembly signatures.

**Impact:** If an attacker can write to any search directory, they can achieve code execution via DLL hijacking.

**Mitigating factor:** The search directories are under `C:\Program Files\Milestone\` which requires administrator privileges to write.

---

### 3.5 Unsafe Pointer Operations in RTSP Driver

| | |
|---|---|
| **Component** | RTSP Device Driver |
| **File** | `Device Drivers/Rtsp/RTSPDriver/Rtsp/RtspClientWorker.cs` |
| **Status** | ⚠️ **NOT FIXED** (FFmpeg interop constraint) |

**Description:** The RTSP driver uses `unsafe` code with FFmpeg native interop. `Marshal.Copy` operations use sizes from FFmpeg-populated structures (`codecpar->extradata_size`, `pkt->size`) without independent bounds validation.

**Impact:** A malicious RTSP server could send crafted media data causing buffer overflows, information disclosure, or denial of service.

**Recommendation:** Add bounds checking before `Marshal.Copy` calls to validate sizes are within expected ranges. Consider running the driver in a separate, low-privilege process.

---

## 4. Medium Severity Findings

### 4.1 RTMP Server Denial of Service

| | |
|---|---|
| **Component** | RTMP Device Driver |
| **Files** | `Device Drivers/Rtmp/RTMPDriver/Rtmp/RtmpServer.cs`, `Device Drivers/Rtmp/RTMPDriver/Config/Constants.cs` |
| **Status** | ⚠️ **EXISTING MITIGATIONS** |

**Description:** While the RTMP server has `MaxConnections`, per-IP rate limiting, `MaxChunkStreamsPerClient`, and `MaxMessageSize` (5 MB) limits, an attacker could still exhaust memory by:
- Creating maximum chunk streams per connection (32), each with a 5 MB buffer
- Opening maximum connections simultaneously

**Existing mitigations:** `MaxConnections = 32`, `MaxChunkStreamsPerClient = 32`, `MaxMessageSize = 5 MB`, `VideoDataTimeoutMs = 15s`.

**Maximum memory per client:** 32 streams × 5 MB = 160 MB (theoretical worst case).

**Recommendation:** Consider adding aggregate memory limits and connection rate throttling.

---

### 4.2 XML Parsing Without Explicit XXE Protection

| | |
|---|---|
| **Component** | SmartBar Plugin, RTMPStreamer Plugin |
| **Files** | `Smart Client Plugins/SmartBar/SmartBarConfig.cs`, `Admin Plugins/RtmpStreamer/Streaming/StreamSessionManager.cs` |
| **Status** | ⚠️ **LOW RISK** |

**Description:** `XDocument.Load()` and `XElement.Parse()` are used without explicitly disabling external entity resolution. However, .NET Framework 4.5.2+ disables DTD processing by default in `XDocument`/`XElement`, mitigating XXE.

**Risk:** Low, because the default settings are safe and the XML sources are local configuration files, not untrusted network input.

---

### 4.3 TLS Certificate Password Stored in Plaintext

| | |
|---|---|
| **Component** | RTMP Device Driver |
| **Files** | `Device Drivers/Rtmp/RTMPDriver/DriverFramework/RTMPDriverConnectionManager.cs` |
| **Status** | ⚠️ **NOT FIXED** |

**Description:** The TLS certificate password for the RTMP driver is stored as a plaintext string in the driver's hardware settings and passed to `X509Certificate2` constructor.

**Recommendation:** Use DPAPI or `SecureString` for the certificate password.

---

### 4.4 Temporary File Security (SnapReport)

| | |
|---|---|
| **Component** | SnapReport Smart Client Plugin |
| **File** | `Smart Client Plugins/SnapReport/Client/SnapReportViewItemWpfUserControl.xaml.cs` |
| **Status** | ⚠️ **LOW RISK** |

**Description:** Camera snapshots are temporarily written to `%TEMP%\SnapReport_{GUID}\` during PDF generation. The temp directory is readable by the current user. GUID naming prevents prediction/collision.

**Remaining risk:** On shared workstations, another process running as the same user could read snapshots during generation.

---

## 5. Low / Informational Findings

### 5.1 Hardcoded Test Credentials

| | |
|---|---|
| **Component** | HttpRequests test server |
| **File** | `Admin Plugins/HttpRequests/test_server.py` |

**Description:** Test credentials (`admin:secret`, `my-bearer-token-123`) are hardcoded in the test server. These are development-only tools and not part of production builds.

**Status:** Acceptable for test infrastructure.

---

### 5.2 RTSP Username Logged

| | |
|---|---|
| **Component** | RTSP Device Driver |
| **File** | `Device Drivers/Rtsp/RTSPDriver/DriverFramework/RTSPDriverConnectionManager.cs` |

**Description:** The RTSP username is logged during connection. While the password is not logged, the username combined with the hostname could assist targeted attacks.

---

### 5.3 Base64 Basic Auth

| | |
|---|---|
| **Component** | HttpRequests Plugin |
| **File** | `Admin Plugins/HttpRequests/Background/HttpRequestExecutor.cs` |

**Description:** HTTP Basic Authentication encodes credentials in Base64, which provides no security (easily reversible). This is per-specification behavior and safe only when TLS is used.

**Recommendation:** Warn users when Basic Auth is configured for non-HTTPS URLs.

---

## 6. Build & CI/CD Pipeline Risks

### 6.1 Path Traversal in `plugins.json` Staging Paths

| | |
|---|---|
| **Files** | `.github/workflows/build-dev.yml`, `.github/workflows/build-release.yml`, `build.ps1` |
| **Status** | ⚠️ **NOT FIXED** |

**Description:** The `extraStagingDirs`, `extraStagingFiles`, and `outputPath` fields in `plugins.json` are used directly in `Copy-Item` commands without path validation. A malicious commit modifying `plugins.json` could set paths like `../../Windows/System32` to copy arbitrary files into build artifacts or the MSI installer.

**Mitigating factor:** Only maintainers can push to `main`; PRs require review.

**Recommendation:** Add path validation in workflows to ensure all staging paths remain within the repository root.

---

### 6.2 Unvalidated MSBuild Project Paths

| | |
|---|---|
| **Files** | All three workflow files (build-dev, build-release, pr-check) |
| **Status** | ⚠️ **NOT FIXED** |

**Description:** The `path` and `extraProjects` fields from `plugins.json` are passed directly to `msbuild`. A malicious `.csproj` file can execute arbitrary code during build via MSBuild targets.

**Mitigating factor:** Same commit-based trust model as staging paths.

**Recommendation:** Validate that project paths don't traverse above the repository root.

---

### 6.3 Matrix Variable Injection in PowerShell

| | |
|---|---|
| **Files** | All workflow files |
| **Status** | ⚠️ **NOT FIXED** |

**Description:** `${{ matrix.name }}` is interpolated into PowerShell `Where-Object` expressions without escaping. A `plugins.json` entry with crafted `name` values containing single quotes could break out of the string context.

**Recommendation:** Use environment variables instead of direct interpolation for matrix values in `run:` blocks, or use PowerShell's `-eq` operator with a variable rather than inline expansion.

---

### 6.4 NuGet Package Versions Not Locked

| | |
|---|---|
| **Status** | ⚠️ **NOT FIXED** |

**Description:** No `packages.lock.json` is used. NuGet restores could pull different (potentially compromised) package versions across builds.

**Recommendation:** Enable NuGet lock files with `RestorePackagesWithLockFile` in `Directory.Build.props`.

---

### 6.5 GitHub Actions Pinned to SHA ✅

All third-party GitHub Actions are pinned to full commit SHAs with version comments:
```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
- uses: NuGet/setup-nuget@d105a947828025cd7a980103c35ba2bfae586d0f # v2.0.2
```
This is best practice and prevents tag-based supply chain attacks.

---

## 7. Positive Security Observations

| Area | Observation |
|------|-------------|
| **RDP Plugin** | Passwords never stored; PublicMode enabled; all redirections disabled except optional clipboard; AuthenticationLevel=2 enforced |
| **RTMP Protocol** | Comprehensive limits: MaxConnections, MaxChunkStreamsPerClient, MaxMessageSize, MaxChunkSize, VideoDataTimeout, per-IP rate limiting |
| **Notepad Plugin** | No file I/O; content stored via SDK abstraction; no XSS risk (WPF TextBox) |
| **SnapReport** | SaveFileDialog for output; GUID-based temp dirs; system fonts only |
| **GitHub Actions** | Actions pinned to SHA; permissions scoped to `contents: read` for PRs |
| **TLS Support** | RTMP driver supports RTMPS with configurable certificates |
| **Process Isolation** | RTMPStreamer uses a separate helper process for streaming |
| **CommunitySDK WebBrowser** | AllowNavigation=false; context menu disabled |

---

## 8. Recommendations Summary

### Immediate (Fixed in this review)

| # | Fix | Severity |
|---|-----|----------|
| 1 | Mask RTMP stream keys in all log output | Critical |
| 2 | Escape process arguments to prevent injection | Critical |
| 3 | Block SSRF in HttpRequests plugin | Critical |
| 4 | Harden SmartBar process execution | Critical |
| 5 | Log warnings on TLS certificate validation bypass | High |

### Short-term (Recommended)

| # | Recommendation | Severity |
|---|---------------|----------|
| 6 | Encrypt stored credentials (DPAPI) in HttpRequests plugin | High |
| 7 | Add path validation in CI/CD staging operations | High |
| 8 | Validate MSBuild project paths stay within repo root | High |
| 9 | Add `packages.lock.json` for NuGet reproducibility | Medium |
| 10 | Pin WiX toolset to specific version | Low |

### Long-term (Architectural)

| # | Recommendation | Severity |
|---|---------------|----------|
| 11 | Avoid embedding credentials in RTSP URLs | High |
| 12 | Add bounds checking to FFmpeg Marshal.Copy operations | High |
| 13 | Consider assembly signing for dynamic loading | Medium |
| 14 | Add aggregate memory limits for RTMP server | Medium |
| 15 | Warn users when Basic Auth is used without HTTPS | Low |
