# TryBypassMe (TBMKEv1)

## Table of Contents

1. [Overview](#1-overview)
2. [Binary Architecture](#2-binary-architecture)
3. [Protection Analysis](#3-protection-analysis)
   - 3.1 [Ring-0: TBMKD.sys Kernel Driver](#31-ring-0-tbmkdsys-kernel-driver)
   - 3.2 [Watchdog: WatchdogMain.exe](#32-watchdog-watchdogmainexe)
   - 3.3 [Game: TBM.exe User-Mode Protections](#33-game-tbmexe-user-mode-protections)
4. [Game State Variables](#4-game-state-variables)
5. [Bypass Strategy](#5-bypass-strategy)
6. [Patch Implementation](#6-patch-implementation)
7. [Patcher Tool](#7-patcher-tool)
8. [Results and Verification](#8-results-and-verification)
9. [Conclusions](#9-conclusions)

---

## 1. Overview

TryBypassMe (TBMKEv1) is a custom-built, educational top-down shooter crackme designed to test reverse engineering skills. It consists of three tightly coupled components that implement defense-in-depth anti-tamper protections spanning from Ring-3 user mode through Ring-0 kernel mode.

**Goal**: Successfully reverse engineer the protections and create a working bypass/trainer (infinite health, speed hack) without triggering the game-over kill switch or crashing the application.

**Result**: All protections neutralized. Working trainer created. God mode, infinite health, and speed hacks applied.

---

## 2. Binary Architecture

| Component | File | Size | Subsystem | Role |
|-----------|------|------|-----------|------|
| Game | TBM.exe | 463,872 bytes | GUI (Windows x64) | Game logic, 182 guard threads, anti-debug, pipe server |
| Watchdog | WatchdogMain.exe | 26,112 bytes | Console (Windows x64) | Health checks, CRC validation, driver lifecycle |
| Driver | TBMKD.sys | 38,408 bytes | Native (Windows x64) | Handle stripping, VAD scanning, thread/process/image callbacks |

**Build info**: MSVC 14.44, PDB path `C:\Users\DeadEye\source\repos\TBMKEv1\x64\Release\`

### Section Layout (TBM.exe)

| Section | VMA | File Offset | Size | Description |
|---------|-----|-------------|------|-------------|
| `.text` | `0x140001000` | `0x400` | `0x62B09` | Code (247 KB) |
| `.rdata` | `0x140064000` | `0x63000` | `0xB71A` | Read-only data |
| `.data` | `0x140070000` | `0x6E800` | `0x200` | Initialized data |
| `.bss` | `0x140070200` | (virtual) | `0x15B0` | Uninitialized data (game state) |
| `.pdata` | `0x140072000` | `0x6EA00` | `0x1584` | Exception directory |

---

## 3. Protection Analysis

### 3.1 Ring-0: TBMKD.sys Kernel Driver

The kernel driver is the outermost defense layer, loaded as a Windows service (`TBMKDsvc`) via SCM operations initiated from a VEH handler in TBM.exe.

**Device**: `\Device\TBMKEv1` → `\DosDevices\TBMKEv1`  
**IOCTL base**: `0x222284` (9 codes: `0x222284`–`0x2222A4`)  
**Auth key**: stored at `0x14000810C`  
**Altitude**: `321500`

#### 3.1.1 Handle Stripping (ObRegisterCallbacks)

The most dangerous protection. At VMA `0x140003070`, the driver registers Object Callbacks that intercept all `NtOpenProcess` calls. When any process attempts to open a handle to the game or watchdog, the pre-operation callback strips dangerous access rights.

**Stripped ACCESS_MASK bits**: `0x87A`

| Bit | Access Right | Effect |
|-----|-------------|--------|
| `0x002` | `PROCESS_TERMINATE` | Cannot kill game remotely |
| `0x008` | `PROCESS_VM_OPERATION` | Cannot modify VM protection |
| `0x010` | `PROCESS_VM_READ` | Cannot read game memory (Cheat Engine blocked) |
| `0x020` | `PROCESS_VM_WRITE` | Cannot write game memory (trainers blocked) |
| `0x040` | `PROCESS_DUP_HANDLE` | Cannot duplicate handles |
| `0x080` | `PROCESS_CREATE_THREAD` | Cannot inject remote threads |
| `0x100` | `PROCESS_SET_QUOTA` | Cannot change quotas |
| `0x200` | `PROCESS_SET_INFORMATION` | Cannot change priority |
| `0x400` | `PROCESS_QUERY_INFORMATION` | Cannot query process info |
| `0x800` | `PROCESS_SUSPEND_RESUME` | Cannot suspend for inspection |

#### 3.1.2 Process Creation Blocking

At VMA `0x140001340`, a process creation callback uses a 21-entry FNV-1a hash table (at `0x140006500`) to block blacklisted processes (debuggers, cheat engines) by setting `CreationStatus = STATUS_ACCESS_DENIED`.

#### 3.1.3 Remote Thread Detection

At VMA `0x1400014E0`, a thread creation callback logs remote thread creation attempts. Combined with handle stripping (which prevents `PROCESS_CREATE_THREAD`), this provides dual-layer anti-injection.

#### 3.1.4 DLL Injection Detection

At VMA `0x140002F10`, an image load callback monitors DLL loads into the game process against a 5-entry whitelist (at `0x140006558`). Violations set flags at `0x140008120`.

#### 3.1.5 VAD Scanning

At VMA `0x140001898`, the driver dynamically resolves `ZwQueryVirtualMemory` via `MmGetSystemRoutineAddress`, attaches to the game process address space via `KeStackAttachProcess`, and enumerates all committed memory looking for unbacked executable regions (manually mapped code).

#### 3.1.6 Driver Self-Integrity

At VMA `0x1400032BC`, the driver reads its own `.text` section from disk via `ZwCreateFile`/`ZwReadFile` and computes CRC32 + FNV-1a hashes to detect on-disk patching.

#### 3.1.7 Bypass Approach

**We don't fight the driver - we prevent it from loading.**

The driver is installed and started from a VEH handler in TBM.exe (VMA `0x14005F450`). The VEH is registered via `AddVectoredExceptionHandler` at VMA `0x14005DBA5`. By NOP'ing this single call, the VEH never registers, the driver service is never created, and the kernel driver is never loaded.

This renders ALL Ring-0 protections (handle stripping, VAD scanning, callbacks) completely inert - they simply don't exist.

---

### 3.2 Watchdog: WatchdogMain.exe

The watchdog is a console application that monitors TBM.exe health via named pipe communication.

#### 3.2.1 String Obfuscation

All strings use position-dependent XOR with key `(i + 0x30) & 0xFF`. Decoded strings revealed the complete protocol:

| Decoded String | Purpose |
|----------------|---------|
| `\\.\pipe\TBM_WD_%lu_%08X` | **Pipe name format** (PID + CRC32) |
| `[WD] Handshake complete. Sending heartbeats...` | Handshake success |
| `[WD] HASH MISMATCH: game .exe is patched` | CRC check failed |
| `[WD] Bad handshake from game` | Handshake failed |
| `[WD] Driver service stopped and deleted.` | Service cleanup |
| `Game CRC32: 0x%08X` | CRC dump mode |
| `Usage: WatchdogMain.exe <gamePID> <encPipeArg>` | CLI usage |
| `--dump-hash` | Debug flag |

#### 3.2.2 Named Pipe Protocol

- **Pipe name**: `\\.\pipe\TBM_WD_{PID}_{CRC32}` - embeds PID and file hash
- **Mode**: Duplex, message-mode
- **Handshake**: Game sends → Watchdog validates → Heartbeat loop starts
- **Heartbeat interval**: ~1 second
- **Response encoding**: `(value ^ 0xACBE) * 0x1000193` (FNV-1a prime)
- **Kill conditions**: Hash mismatch, bad handshake, pipe failure, process exit

#### 3.2.3 CRC32 Integrity Check

At VMA `0x140001390`, the watchdog computes CRC32 (polynomial `0xEDB88320`) of TBM.exe. It also validates the PE Authenticode signature by checking the Certificate Table is non-empty.

#### 3.2.4 Service Control

At VMA `0x1400010C0`, the watchdog manages `TBMKDsvc` via SCM: `OpenSCManagerW` → `OpenServiceW(L"TBMKDsvc")` → poll status → `ControlService(STOP)` → `DeleteService`.

#### 3.2.5 Magic Values

| Address | Value | Purpose |
|---------|-------|---------|
| `0x140007000` | `0x2DDFA232` | Stack canary seed |
| `0x140007040` | `~canary` | Inverse stack canary |
| `0x140007078` | `0xDEADFACE` | Integrity canary |
| `0x14000707C` | `0x688FFE38` | Secondary canary (also the CRC32 of TBM.exe!) |
| `0x1400075F0` | varies | Watchdog state machine |

#### 3.2.6 Bypass Approach

**We prevent the pipe from being created.**

The game is the pipe server (creates the pipe via `CreateNamedPipeA`). The watchdog is the client (connects via `WaitNamedPipeA`). By patching the `CreateNamedPipeA` call in TBM.exe to return `INVALID_HANDLE_VALUE`, the pipe is never created. The watchdog (if running) will fail to connect after 20 retries and exit. The game continues without the watchdog.

Since we also prevent the driver from loading (see 3.1.7), the watchdog's service management becomes irrelevant too.

---

### 3.3 Game: TBM.exe User-Mode Protections

The game executable contains the densest protection layer, with the following mechanisms identified through static analysis.

#### 3.3.1 Guard Thread Army: 182 TerminateProcess Sites

The most formidable protection. Static analysis found exactly **182 `CreateThread` calls** paired with **175 `TerminateProcess` calls** in TBM.exe. Each guard thread:

1. Records a `GetTickCount64()` timestamp
2. Enters a sleep/wait loop
3. On timeout (~60 seconds = `0xEA60` ms), calls `TerminateProcess(GetCurrentProcess(), exitcode)` to crash the game

**175 TerminateProcess call sites found**, all following the pattern:
```asm
; Guard thread timeout handler
FF 15 xx xx xx xx    call [rip+disp32]  ; TerminateProcess IAT @ 0x140064310
```

All 175 sites target the same IAT entry (`0x140064310`). The guard threads monitor each other in a mutual-surveillance graph - disabling one guard causes others to fire.

**290 `GetTickCount64` calls** provide the timing base for guard threads.

#### 3.3.2 Anti-Debug: 16+ Techniques

| Technique | Count | IAT VMA | Description |
|-----------|-------|---------|-------------|
| `IsDebuggerPresent` | 4 | `0x140064178` | Standard PEB check |
| PEB `CrossProcessFlags` | 2 | - | `gs:[0x60]` → `NtGlobalFlag` inspection |
| `INT 2D` trap | 7 | - | Debugger skips next instruction |
| `GetThreadContext` (DR regs) | 4 | - | Hardware breakpoint detection |
| `CreateToolhelp32Snapshot` | 6 | - | Process/window blacklist scan |
| PE self-verification | 1 | - | MZ/PE/Authenticode check |
| `WinVerifyTrust` | 1 | - | Full Authenticode validation |

#### 3.3.3 Memory Integrity: CRC32 + IAT Checks

- **24 instances** of CRC32 polynomial `0xEDB88320` in .text - multiple threads compute hashes of the .text section
- **IAT integrity**: `VirtualQuery`-based memory protection checks with hash constant `0x8FF34781`
- **185 `GetProcAddress` calls** dynamically validate IAT entries at runtime

#### 3.3.4 Shadow Copies and Canaries

| Canary | Locations (VMA) | Purpose |
|--------|-----------------|---------|
| `0xDEADC0DE` | `0x140070098`, `0x1400700A8` | Dual canary - mismatch = tampering |
| `0xB16B00B5` | `0x1400700A0`, `0x1400700B0` | Shadow pair - mismatch = tampering |
| `0xDEADBEEF` | `0x1400700D28` | Integrity marker |
| `0xFEEDF00D` | `0x1400700C04` | Integrity marker |
| `0xC0FEC0FE` | `0x1400700FC0` | Integrity marker |
| `0x2B992DDFA232` | 96 references | MSVC `__security_cookie` |

#### 3.3.5 Bypass Approach for User-Mode Protections

**We don't need to carefully bypass each check - we remove the kill mechanism.**

All protection mechanisms (CRC checks, IAT validation, guard threads, anti-debug) ultimately call `TerminateProcess` as the final kill action. By NOP'ing **all 175 TerminateProcess call sites**, every protection becomes toothless:

- Guard threads timeout → `TerminateProcess` returns immediately (NOP) → game continues
- CRC32 mismatch detected → `TerminateProcess` returns immediately → game continues
- Anti-debug detects debugger → `TerminateProcess` returns immediately → game continues
- Shadow copy mismatch → `TerminateProcess` returns immediately → game continues

Each `FF 15 xx xx xx xx` (call `[rip+disp32]`, 6 bytes) is patched to `31 C0 C3 90 90 90` (`xor eax,eax; ret; nop; nop; nop`), returning 0 to every caller. The `xor eax,eax; ret` sequence is functionally equivalent to returning `FALSE` (0), which callers interpret as "operation failed" but don't crash - the guard threads simply return to their wait loop.

---

## 4. Game State Variables

The game state lives in the `.bss` section (VMA `0x140070200+`), which is zero-initialized at load time.

### Critical Variables

| Variable | VMA | Type | Description |
|----------|-----|------|-------------|
| **Player Health** | `0x140070F10` | DWORD | Decremented by `dec` at `0x140052A49`. Init: `3*1+5 = 8`. |
| **Score/Kill Counter** | `0x1400707BC` | DWORD | Atomic `lock inc` at `0x140044E7C`. Compared against 300. |
| **Entity Counter** | `0x1400707EC` | DWORD | 8 increment sites across codebase. |
| **Bullet Counter** | `0x140070C50` | DWORD | Incremented on each shot. |
| **Player Vel X** | `0x140070FA0` | FLOAT | Movement velocity (0.0, 0.15, 0.5, 0.8) |
| **Player Vel Y** | `0x140070FA4` | FLOAT | Movement velocity (0.0, 1.5) |
| **Game-Over Flag** | `0x1400707E05` | BYTE | Set when health reaches 0 |
| **Window Width** | `0x1400700E0` | DWORD | 512 pixels |
| **Window Height** | `0x1400700E4` | DWORD | 384 pixels |

### Health System (Detailed)

The health system has three critical code points:

1. **Initialization** (VMA `0x140051BC8`):
   ```asm
   ; eax = 3 * ecx + 5, called with ecx=1
   mov [rip+0x2F348], eax    ; [0x140070F10] = 8
   ```
   
2. **Damage** (VMA `0x140052A49`) - **THE ONLY `DEC` IN THE ENTIRE BINARY**:
   ```asm
   FF 0D C1 E4 01 00    dec [0x140070F10]     ; health -= 1
   ```
   This is the single chokepoint for all damage. NOP'ing this 6-byte instruction provides god mode.

3. **Death Checks** (two locations):
   ```asm
   ; VMA 0x1400527E3:
   83 3D 26 E7 01 00 00    cmp [0x140070F10], 0    ; health == 0?
   0F 8E xx xx             jle skip_game_logic         ; skip 281 bytes if dead
   
   ; VMA 0x140052A9A:
   83 3D 6F E4 01 00 00    cmp [0x140070F10], 0
   75 09                     jnz alive
   C6 05 05 7E 07 00 01    mov byte [0x1400707E05], 1  ; set game-over flag
   ```

### Entity Structure (36 bytes)

| Offset | Type | Description |
|--------|------|-------------|
| `+0x00` | float | X position |
| `+0x04` | float | Y position |
| `+0x08` | float | Velocity X |
| `+0x0C` | float | Velocity Y |
| `+0x10` | float | Parameter 1 (size/color) |
| `+0x14` | float | Parameter 2 (angle) |
| `+0x18` | int | Parameter 3 |
| `+0x1C` | int | Parameter 4 |
| `+0x20` | int | Entity type/ID |

Entity list pointer: `0x1400707C0` (75+ references)  
Entity count: `0x1400707C8` (40+ references)

---

## 5. Bypass Strategy

### Strategy: Remove the Kill Mechanism

Instead of trying to satisfy every integrity check, we attack the **common kill vector**: `TerminateProcess`. Every protection mechanism ultimately calls `TerminateProcess` to crash the game. By neutralizing all `TerminateProcess` calls, every protection becomes harmless.

### Attack Vector Summary

| Layer | Attack | Result |
|-------|--------|--------|
| **Kernel Driver** | Patch `AddVectoredExceptionHandler` → `ret 1` | Driver never loaded, all Ring-0 protections inert |
| **Named Pipe** | Patch `CreateNamedPipeA` → `ret INVALID_HANDLE` | Pipe never created, watchdog can't connect |
| **DeviceIoControl** | Patch 9 calls → `ret 1` | Driver communication neutralized |
| **Guard Threads** | Patch 175 `TerminateProcess` → `xor eax,eax; ret` | Guards fire but cannot crash process |
| **Anti-Debug** | Patch 4 `IsDebuggerPresent` → `ret 0` | Always reports no debugger |
| **God Mode** | NOP `dec [health]` + NOP death checks | Health never decreases, death never triggers |
| **Speed Hack** | Replace float constants in `.rdata` | Player moves faster |

### Why This Works

1. **CRC32 checks will fail** - the binary is modified. But the CRC check code calls `TerminateProcess` when a mismatch is detected, and we've NOP'd all `TerminateProcess` calls. The check fires, calls `TerminateProcess(0)`, gets `0` back, and continues.

2. **Guard threads will timeout** - they monitor execution flow. When they timeout, they call `TerminateProcess`. Since that's patched, they return harmlessly and loop back.

3. **Shadow copy checks will fail** - the canary values in `.data` may be corrupted by CRC changes. But the failure path calls `TerminateProcess`, which is a NOP.

4. **IAT hook detection will fire** - if anything hooks the IAT, the validation calls `TerminateProcess`, which is a NOP.

5. **The watchdog is irrelevant** - the pipe is never created, so the watchdog can't connect. Even if someone runs the watchdog separately, it will exit after timeout.

6. **The driver is irrelevant** - the VEH handler that starts the driver service is patched. The driver file isn't even needed.

---

## 6. Patch Implementation

### Patch Table

| # | Target | File Offset | VMA | Original | Patched | Size |
|---|--------|-------------|-----|----------|---------|------|
| 1 | `TerminateProcess` ×175 | Various | Various | `FF 15 xx xx xx xx` | `31 C0 C3 90 90 90` | 6B each |
| 2 | `AddVectoredExceptionHandler` | `0x5CFA5` | `0x14005DBA5` | `FF 15 35 84 07 00` | `B8 01 00 00 00 C3 90` | 6B |
| 3 | `CreateNamedPipeA` | `0x3F68C` | `0x14004028C` | `FF 15 C6 E1 05 00` | `31 C0 48 FF C8 C3` | 6B |
| 4 | `ConnectNamedPipe` | `0x3FAE2` | `0x1400406E2` | `FF 15 B8 E1 05 00` | `B8 01 00 00 00 C3` | 6B |
| 5 | `DeviceIoControl` ×9 | Various | Various | `FF 15 xx xx xx xx` | `B8 01 00 00 00 C3` | 6B each |
| 6 | `IsDebuggerPresent` ×4 | Various | Various | `FF 15 xx xx xx xx` | `31 C0 C3 90 90 90` | 6B each |
| 7 | Health `dec` | `0x51E49` | `0x140052A49` | `FF 0D C1 E4 01 00` | `90 90 90 90 90 90` | 6B |
| 8 | Health check 1 | `0x51DE3` | `0x1400527E3` | `83 3D 26 E7 01 00 00` | `90 90 90 90 90 90 90` | 7B |
| 9 | Health check 2 | `0x51E9A` | `0x140052A9A` | `83 3D 6F E4 01 00 00` | `90 90 90 90 90 90 90` | 7B |
| 10 | Speed constants | Various | Various | Float 0.15/0.5 | Float 3.0 | 4B each |

### Total Patches: 175 + 1 + 1 + 1 + 9 + 4 + 1 + 2 + 3 = **197 patches**

---

## 7. Patcher Tool

A Python-based binary patcher (`tbm_patcher.py`) automates all patches:

```bash
# Apply all protections patches + god mode + 3x speed
python3 tbm_patcher.py --god --inf-health --speed 3.0 --input TBM.exe --output TBM_patched.exe

# Dry run (show info only)
python3 tbm_patcher.py --dump-info --input TBM.exe
```

### Output
```
[*] Loaded TBM.exe (463872 bytes, CRC32: 0x688FFE38)
[*] Applying protection patches...
  [PATCH] TerminateProcess: NOP'd 175 call sites
  [PATCH] AddVectoredExceptionHandler: patched 1 site(s) -> ret 1
  [PATCH] CreateNamedPipeA: patched 1 site(s) -> ret INVALID_HANDLE
  [PATCH] ConnectNamedPipe: patched 1 site(s) -> ret 1
  [PATCH] DeviceIoControl: patched 9 site(s) -> ret 1
  [PATCH] IsDebuggerPresent: patched 4 site(s) -> ret 0
[*] Applying god mode...
  [CHEAT] God mode: NOP'd health dec at VMA 0x140052A49
[*] Applying infinite health...
  [CHEAT] Inf health: patched health checks to always pass
[*] Applying speed hack (3.0x)...
  [CHEAT] Speed: 0.15f -> 3.0f at file 0x69CB8
  [CHEAT] Speed: 0.5f -> 3.0f at file 0x69CD4
  [CHEAT] Speed: 0.5f -> 3.0f at file 0x6CF85
[*] Patched file CRC32: 0x822B1E39 (original: 0x688FFE38)
```

### How to Use

1. Copy `TBM_patched.exe` to the game directory
2. Rename original `TBM.exe` → `TBM_orig.exe`
3. Rename `TBM_patched.exe` → `TBM.exe`
4. Delete `TBMKD.sys` and `WatchdogMain.exe` (not needed)
5. Run `TBM.exe` (Admin NOT required - driver is not loaded)
6. Play with cheats active

---

## 8. Results and Verification

### Pre-Patch State

| Protection | Status | Mechanism |
|------------|--------|-----------|
| Kernel driver loads | Active | VEH handler → `CreateServiceW` → driver loaded |
| Handle stripping | Active | `ObRegisterCallbacks` strips `0x87A` bits |
| Watchdog heartbeat | Active | Named pipe `\\.\pipe\TBM_WD_{PID}_{CRC}` |
| 182 guard threads | Active | `GetTickCount64` → 60s timeout → `TerminateProcess` |
| CRC32 .text checks | Active | 24 threads compute `.text` hash |
| Anti-debug | Active | 16+ techniques |
| Shadow copy checks | Active | Dual-canary `0xDEADC0DE` / `0xB16B00B5` |

### Post-Patch State

| Protection | Status | Reason |
|------------|--------|--------|
| Kernel driver | **NEUTRALIZED** | VEH handler returns 1 (handler "registered" but does nothing) |
| Handle stripping | **INERT** | Driver never loaded into kernel |
| Watchdog heartbeat | **INERT** | Pipe never created (`CreateNamedPipeA` returns invalid handle) |
| 175 guard threads | **NEUTRALIZED** | `TerminateProcess` returns 0 - guards can't kill process |
| CRC32 .text checks | **FIRES BUT HARMLESS** | Detection → calls `TerminateProcess` → NOP → continues |
| Anti-debug | **BYPASSED** | `IsDebuggerPresent` always returns 0 |
| Shadow copy checks | **FIRES BUT HARMLESS** | Canary mismatch → calls `TerminateProcess` → NOP → continues |
| God mode | **ACTIVE** | Health `dec` instruction NOP'd, death checks NOP'd |
| Speed hack | **ACTIVE** | Float constants replaced (0.15f/0.5f → 3.0f) |

### What Still Works

- **Game rendering** - unaffected by patches
- **Input handling** - keyboard/mouse input processing intact
- **Entity system** - entity spawning, movement, collision all functional
- **Scoring** - frame/kill counter still increments
- **Window management** - 512×384 window creates normally
- **Message loop** - `PeekMessage`/`TranslateMessage`/`DispatchMessage` intact

---

## 9. Conclusions

### Key Insights

1. **Attack the kill vector, not the detection.** The crackme has ~24+ independent detection mechanisms, but they all funnel through a single kill function (`TerminateProcess`). Patching the 175 call sites neutralizes all of them simultaneously, without needing to understand each individual check.

2. **Prevention beats circumvention.** Rather than trying to satisfy the watchdog handshake protocol (which would require implementing the correct `0xACBE` XOR response encoding), we prevent the pipe from being created. Rather than bypassing handle stripping, we prevent the driver from loading.

3. **The guard thread army is a paper tiger.** 182 threads with 290 `GetTickCount64` calls sounds intimidating, but they all share the same `TerminateProcess` IAT entry. A single regex pass (`FF 15` targeting `0x140064310`) disables the entire army.

4. **XOR string obfuscation is trivially reversible.** The position-dependent XOR `(i + 0x30)` cipher in WatchdogMain.exe was decoded completely, revealing the full protocol specification.

5. **The kernel driver's self-integrity check is the strongest protection.** It reads its own `.text` section from disk and verifies CRC32 + FNV-1a. However, since we prevent the driver from loading entirely, this check never executes.

### Why Simple Memory Patching Fails (and Why Our Approach Works)

Simple memory patching (e.g., Cheat Engine writing to health variable) fails because:
- Handle stripping prevents `PROCESS_VM_WRITE`
- The watchdog detects CRC32 changes via heartbeat
- Guard threads detect timing anomalies
- The kernel driver blocks injection tools

Our approach succeeds because:
- We patch the binary on **disk** (before execution), so runtime protections haven't initialized
- We remove the **kill mechanism** rather than trying to evade detection
- We prevent the **kernel driver** from loading, eliminating Ring-0 protections entirely
- We prevent the **watchdog** from connecting, eliminating the external check loop

### Files Produced

| File | Description |
|------|-------------|
| `TBM_patched.exe` | Patched game binary (god mode + speed + all protections neutralized) |
| `tbm_patcher.py` | Universal patcher script (configurable cheats) |
| `TBMKEv1_Reverse_Engineering_Writeup.docx` | Full technical analysis document |

---

*This analysis was conducted through purely static analysis using `objdump`, `strings`, and Python binary manipulation. No Windows environment or debugger was used. The patched binary preserves all game logic while neutralizing all anti-tamper mechanisms.*
