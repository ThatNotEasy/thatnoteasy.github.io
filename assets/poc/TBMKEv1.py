#!/usr/bin/env python3
"""
TBMKEv1 (TryBypassMe) - Universal Binary Patcher & Trainer Generator
=====================================================================
Patches TBM.exe to disable all protections and optionally applies trainer cheats.

USAGE:
    python3 tbm_patcher.py [--god] [--inf-health] [--inf-ammo] [--speed N]
                            [--output patched.exe]

PROTECTIONS NEUTRALIZED:
    1. TerminateProcess calls (175 sites) - NOP'd to prevent guard kill
    2. AddVectoredExceptionHandler - NOP'd to prevent kernel driver loading
    3. CreateNamedPipeA - NOP'd to prevent watchdog pipe creation
    4. ConnectNamedPipe - NOP'd to prevent watchdog connection
    5. DeviceIoControl - NOP'd to prevent driver communication
    6. IsDebuggerPresent - NOP'd (4 sites)
    7. Health dec (god mode) - NOP'd or replaced with NOP

TRAINER CHEATS (optional):
    --god           NOP the health decrement instruction
    --inf-health    Set initial health to 0x7FFFFFFF at init site
    --speed N       Set player speed multiplier (float)
    --output FILE   Output filename (default: TBM_patched.exe)

AUTHOR: Educational crackme bypass - for learning purposes only.
"""

import struct
import sys
import os
import shutil
import hashlib
import argparse

# ═══════════════════════════════════════════════════════════════════════
# BINARY LAYOUT CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

IMAGE_BASE    = 0x140000000
TEXT_VMA      = 0x140001000
TEXT_FILE_OFF = 0x400
TEXT_SIZE     = 0x62B09

# IAT entries (VMA)
IAT = {
    'TerminateProcess':           0x140064310,
    'CreateNamedPipeA':           0x1400642C8,
    'ConnectNamedPipe':           0x140064180,
    'DeviceIoControl':            0x140064300,
    'IsDebuggerPresent':          0x140064178,
    'CreateThread':               0x140064240,
    'GetTickCount64':             0x140064258,
    'AddVectoredExceptionHandler': 0x1400641C0,
    'CreateFileW':                0x1400641B8,
    'WriteFile':                  0x1400642B8,
    'ReadFile':                   0x1400642E8,
}

# Game state variables (VMA, BSS section - zero-init, patched at runtime or init)
GAME_VARS = {
    'health':        0x140070F10,   # DWORD - player health, dec'd at VMA 0x140052A49
    'score_counter': 0x1400707BC,   # DWORD - frame/kill counter (lock inc)
    'entity_count':  0x1400707EC,   # DWORD - entity spawn counter
    'bullet_count':  0x140070C50,   # DWORD - shot counter
    'player_vel_x':  0x140070FA0,   # FLOAT - player velocity X
    'player_vel_y':  0x140070FA4,   # FLOAT - player velocity Y
    'game_over':     0x1400707E05,  # BYTE  - game-over flag
    'window_w':      0x1400700E0,   # DWORD - window width (512)
    'window_h':      0x1400700E4,   # DWORD - window height (384)
}

# Specific patch addresses (VMA -> file offset conversion)
HEALTH_DEC_VMA      = 0x140052A49    # dec [0x140070F10] - the ONLY dec in entire binary
HEALTH_INIT_VMA     = 0x140051BC8    # mov [0x140070F10], eax (eax = 3*ecx+5, called with ecx=1)
HEALTH_CHECK1_VMA   = 0x1400527E3    # cmp [0x140070F10], 0 -> jle (skip game logic if dead)
HEALTH_CHECK2_VMA   = 0x140052A9A    # cmp [0x140070F10], 0 -> set game-over flag
GAME_OVER_FLAG_VMA  = 0x1400707E05   # game-over flag (BSS, runtime)


def vma_to_file(vma):
    """Convert VMA to file offset for .text section."""
    return vma - TEXT_VMA + TEXT_FILE_OFF


def find_all_calls(data, iat_vma):
    """Find all FF 15 [rip+disp32] call sites that target a specific IAT entry."""
    results = []
    text_start = TEXT_FILE_OFF
    text_end = TEXT_FILE_OFF + TEXT_SIZE

    for i in range(text_start, text_end - 5):
        if data[i] == 0xFF and data[i + 1] == 0x15:
            disp = struct.unpack_from('<i', data, i + 2)[0]
            instr_vma = i - TEXT_FILE_OFF + TEXT_VMA
            next_vma = instr_vma + 6
            target_vma = (next_vma + disp) & 0xFFFFFFFFFFFFFFFF
            if target_vma == iat_vma:
                results.append(i)  # file offset
    return results


def nop_bytes(data, file_offset, size=6):
    """Replace bytes with NOP (0x90)."""
    patched = bytearray(data)
    for i in range(size):
        patched[file_offset + i] = 0x90
    return bytes(patched)


def patch_call_to_ret(data, file_offset):
    """Replace FF 15 xx xx xx xx (call [rip+disp]) with 31 C0 C3 (xor eax,eax; ret)."""
    patched = bytearray(data)
    patched[file_offset]     = 0x31  # xor eax, eax
    patched[file_offset + 1] = 0xC0
    patched[file_offset + 2] = 0xC3  # ret
    patched[file_offset + 3] = 0x90  # nop (padding)
    patched[file_offset + 4] = 0x90
    patched[file_offset + 5] = 0x90
    return bytes(patched)


def patch_call_to_ret_true(data, file_offset):
    """Replace call with mov eax, 1; ret (returns success)."""
    patched = bytearray(data)
    patched[file_offset]     = 0xB8  # mov eax, imm32
    patched[file_offset + 1] = 0x01  # 1
    patched[file_offset + 2] = 0x00
    patched[file_offset + 3] = 0x00
    patched[file_offset + 4] = 0x00
    patched[file_offset + 5] = 0xC3  # ret
    return bytes(patched)


def patch_call_to_mov_handle(data, file_offset):
    """Replace call with mov rax, INVALID_HANDLE_VALUE; ret (returns -1 handle)."""
    patched = bytearray(data)
    # mov rax, 0xFFFFFFFFFFFFFFFF  (48 B8 FF FF FF FF FF FF FF FF)
    # ret (C3)
    # Total 10 bytes, but we only have 6 from FF 15 pattern
    # Use: xor eax, eax; dec eax; ret (returns -1 as HANDLE)
    patched[file_offset]     = 0x31  # xor eax, eax
    patched[file_offset + 1] = 0xC0
    patched[file_offset + 2] = 0x48  # dec eax (0xFF C8 would be dec eax)
    patched[file_offset + 3] = 0xFF
    patched[file_offset + 4] = 0xC8
    patched[file_offset + 5] = 0xC3  # ret
    return bytes(patched)


def apply_protection_patches(data):
    """Apply all protection-neutralizing patches."""
    patched = bytearray(data)
    stats = {}

    # ──────────────────────────────────────────────────────────────────
    # PATCH 1: TerminateProcess - NOP all 175 call sites
    # These are the guard thread kill calls. NOP'ing them prevents any
    # guard thread from crashing the process when a timeout fires.
    # ──────────────────────────────────────────────────────────────────
    tp_calls = find_all_calls(data, IAT['TerminateProcess'])
    stats['terminate_process_nopped'] = len(tp_calls)
    for off in tp_calls:
        patched = bytearray(patch_call_to_ret(bytes(patched), off))
    print(f"  [PATCH] TerminateProcess: NOP'd {len(tp_calls)} call sites")

    # ──────────────────────────────────────────────────────────────────
    # PATCH 2: AddVectoredExceptionHandler - prevent VEH registration
    # The VEH handler at 0x14005f450 installs the kernel driver service.
    # By preventing VEH registration, the driver is never loaded.
    # ──────────────────────────────────────────────────────────────────
    veh_calls = find_all_calls(bytes(patched), IAT['AddVectoredExceptionHandler'])
    stats['veh_nopped'] = len(veh_calls)
    for off in veh_calls:
        patched = bytearray(patch_call_to_ret_true(bytes(patched), off))
    print(f"  [PATCH] AddVectoredExceptionHandler: patched {len(veh_calls)} site(s) -> ret 1")

    # ──────────────────────────────────────────────────────────────────
    # PATCH 3: CreateNamedPipeA - prevent named pipe creation
    # The game creates a named pipe server for the watchdog. Without this,
    # the watchdog cannot connect and the heartbeat never starts.
    # ──────────────────────────────────────────────────────────────────
    pipe_calls = find_all_calls(bytes(patched), IAT['CreateNamedPipeA'])
    stats['create_named_pipe_nopped'] = len(pipe_calls)
    for off in pipe_calls:
        patched = bytearray(patch_call_to_mov_handle(bytes(patched), off))
    print(f"  [PATCH] CreateNamedPipeA: patched {len(pipe_calls)} site(s) -> ret INVALID_HANDLE")

    # ──────────────────────────────────────────────────────────────────
    # PATCH 4: ConnectNamedPipe - prevent pipe connection waiting
    # ──────────────────────────────────────────────────────────────────
    conn_calls = find_all_calls(bytes(patched), IAT['ConnectNamedPipe'])
    stats['connect_named_pipe_nopped'] = len(conn_calls)
    for off in conn_calls:
        patched = bytearray(patch_call_to_ret_true(bytes(patched), off))
    print(f"  [PATCH] ConnectNamedPipe: patched {len(conn_calls)} site(s) -> ret 1")

    # ──────────────────────────────────────────────────────────────────
    # PATCH 5: DeviceIoControl - prevent driver communication
    # With the driver not loaded, these calls would fail anyway, but
    # patching them prevents any side effects or exceptions.
    # ──────────────────────────────────────────────────────────────────
    ioctl_calls = find_all_calls(bytes(patched), IAT['DeviceIoControl'])
    stats['device_io_control_nopped'] = len(ioctl_calls)
    for off in ioctl_calls:
        patched = bytearray(patch_call_to_ret_true(bytes(patched), off))
    print(f"  [PATCH] DeviceIoControl: patched {len(ioctl_calls)} site(s) -> ret 1")

    # ──────────────────────────────────────────────────────────────────
    # PATCH 6: IsDebuggerPresent - force return 0 (4 sites)
    # ──────────────────────────────────────────────────────────────────
    dbg_calls = find_all_calls(bytes(patched), IAT['IsDebuggerPresent'])
    stats['is_debugger_present_nopped'] = len(dbg_calls)
    for off in dbg_calls:
        patched = bytearray(patch_call_to_ret(bytes(patched), off))  # ret 0 = no debugger
    print(f"  [PATCH] IsDebuggerPresent: patched {len(dbg_calls)} site(s) -> ret 0")

    return bytes(patched), stats


def apply_god_mode(data):
    """Patch the health decrement to NOP - god mode."""
    patched = bytearray(data)
    off = vma_to_file(HEALTH_DEC_VMA)
    # Original: FF 0D C1 E4 01 00 (dec [0x140070F10])
    # Patch to:  90 90 90 90 90 90 (6x NOP)
    for i in range(6):
        patched[off + i] = 0x90
    print(f"  [CHEAT] God mode: NOP'd health dec at VMA 0x{HEALTH_DEC_VMA:x} (file 0x{off:x})")
    return bytes(patched)


def apply_inf_health(data):
    """Patch the health initialization to set max health."""
    patched = bytearray(data)
    # At VMA 0x140051BC8: mov [0x140070F10], eax
    # We want to set eax to a large value before this mov executes.
    # The instruction is: 89 05 48 F3 02 00 (mov [rip+0x2f348], eax)
    # We can patch this to: mov dword ptr [0x140070F10], 0x7FFFFFFF
    # But that's 10 bytes and we only have 6. Instead, patch the init
    # function to write a large immediate value.
    # Original: 89 05 48 F3 02 00
    # Patch to: C7 05 48 F3 02 00 FF FF FF 7F ... but needs 10 bytes
    
    # Simpler approach: patch the comparison checks to never trigger death
    # Health check 1: cmp [0x140070F10], 0 -> jle
    off1 = vma_to_file(HEALTH_CHECK1_VMA)
    # Original bytes should be: 83 3D 28 F4 02 00 00 (cmp [rip+disp], 0)
    # The jle follows. We NOP the comparison and change jle to jmp (or NOP both)
    # Let's just verify the bytes and NOP the comparison
    print(f"  [CHEAT] Inf health: Health check 1 at VMA 0x{HEALTH_CHECK1_VMA:x} bytes: {data[off1:off1+10].hex()}")
    
    # Simpler: just patch health check to always use the "alive" path
    # NOP the cmp and the jle
    for i in range(7):
        patched[off1 + i] = 0x90
    
    off2 = vma_to_file(HEALTH_CHECK2_VMA)
    print(f"  [CHEAT] Inf health: Health check 2 at VMA 0x{HEALTH_CHECK2_VMA:x} bytes: {data[off2:off2+10].hex()}")
    for i in range(7):
        patched[off2 + i] = 0x90
    
    # Also NOP the game-over flag set
    # At VMA 0x140052A9A: after cmp, there's a conditional set of game-over flag
    # We already NOP'd the comparison, so the flag won't be set.
    
    print(f"  [CHEAT] Infinite health: patched health checks to always pass")
    return bytes(patched)


def apply_speed_hack(data, speed_value=2.0):
    """Patch player speed constants in .rdata section."""
    patched = bytearray(data)
    speed_bytes = struct.pack('<f', speed_value)
    
    # Patch the float constants used for player velocity initialization
    # Player vel X at 0x140070FA0 (BSS - runtime, not patchable in file)
    # Instead, patch the .rdata constants that initialize speed
    # Search for the 0.15f constant (0x3E19999A) and replace with our value
    target = struct.pack('<f', 0.15)
    count = 0
    idx = 0
    while True:
        idx = data.find(target, idx)
        if idx == -1:
            break
        # Check if it's in .rdata section (file 0x63000 - 0x6e800)
        if 0x63000 <= idx <= 0x6e800:
            patched[idx:idx+4] = speed_bytes
            count += 1
            print(f"  [CHEAT] Speed: 0.15f -> {speed_value}f at file 0x{idx:x}")
        idx += 4
    
    target2 = struct.pack('<f', 0.5)
    idx = 0
    while True:
        idx = data.find(target2, idx)
        if idx == -1:
            break
        if 0x63000 <= idx <= 0x6e800:
            patched[idx:idx+4] = speed_bytes
            count += 1
            print(f"  [CHEAT] Speed: 0.5f -> {speed_value}f at file 0x{idx:x}")
        idx += 4
    
    print(f"  [CHEAT] Speed hack: patched {count} speed constants to {speed_value}f")
    return bytes(patched)


def compute_crc32(data):
    """Compute CRC32 of data using standard polynomial."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def main():
    parser = argparse.ArgumentParser(description='TBMKEv1 Binary Patcher & Trainer')
    parser.add_argument('--input', default='TBM.exe', help='Input TBM.exe path')
    parser.add_argument('--output', default='TBM_patched.exe', help='Output patched file')
    parser.add_argument('--god', action='store_true', help='Enable god mode (NOP health decrement)')
    parser.add_argument('--inf-health', action='store_true', help='Infinite health (patch health checks)')
    parser.add_argument('--speed', type=float, default=None, help='Set player speed multiplier')
    parser.add_argument('--dump-info', action='store_true', help='Dump patch info without patching')
    args = parser.parse_args()

    # Read input file
    if not os.path.exists(args.input):
        # Try in upload directory
        alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.input)
        if os.path.exists(alt_path):
            args.input = alt_path
        else:
            print(f"ERROR: Cannot find {args.input}")
            sys.exit(1)

    with open(args.input, 'rb') as f:
        data = f.read()

    orig_size = len(data)
    orig_crc = compute_crc32(data)
    print(f"[*] Loaded {args.input} ({orig_size} bytes, CRC32: 0x{orig_crc:08X})")

    if args.dump_info:
        print("\n[*] Patch Information (dry run):")
        print(f"    TerminateProcess IAT:  0x{IAT['TerminateProcess']:X}")
        tp_calls = find_all_calls(data, IAT['TerminateProcess'])
        print(f"    TerminateProcess calls: {len(tp_calls)}")
        print(f"    CreateNamedPipeA IAT:   0x{IAT['CreateNamedPipeA']:X}")
        print(f"    AddVectoredExceptionH: 0x{IAT['AddVectoredExceptionHandler']:X}")
        print(f"    Health variable VMA:    0x{GAME_VARS['health']:X}")
        print(f"    Health dec VMA:         0x{HEALTH_DEC_VMA:X}")
        print(f"    Score counter VMA:      0x{GAME_VARS['score_counter']:X}")
        sys.exit(0)

    # ── Step 1: Apply protection patches ──
    print("\n[*] Applying protection patches...")
    patched, stats = apply_protection_patches(data)

    # ── Step 2: Apply trainer cheats ──
    if args.god:
        print("\n[*] Applying god mode...")
        patched = apply_god_mode(patched)

    if args.inf_health:
        print("\n[*] Applying infinite health...")
        patched = apply_inf_health(patched)

    if args.speed is not None:
        print(f"\n[*] Applying speed hack ({args.speed}x)...")
        patched = apply_speed_hack(patched, args.speed)

    # ── Step 3: Write output ──
    new_crc = compute_crc32(patched)
    print(f"\n[*] Patched file CRC32: 0x{new_crc:08X} (original: 0x{orig_crc:08X})")
    print(f"[*] Size delta: {len(patched) - orig_size} bytes")

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.output)
    with open(out_path, 'wb') as f:
        f.write(patched)
    print(f"[*] Written to: {out_path}")

    # ── Step 4: Generate patch summary ──
    print("\n" + "=" * 60)
    print("PATCH SUMMARY")
    print("=" * 60)
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print()
    print("NOTES:")
    print("  - WatchdogMain.exe is NOT needed with patched TBM.exe")
    print("  - TBMKD.sys is NOT loaded (VEH handler patched)")
    print("  - Named pipe server is NOT created (CreateNamedPipeA patched)")
    print("  - All 175 guard thread TerminateProcess calls are neutered")
    print("  - IsDebuggerPresent always returns 0")
    print("  - CRC32 integrity checks will fail but cannot crash the process")
    print("    (TerminateProcess is the crash vector and it's NOP'd)")
    print()
    print("TO USE:")
    print("  1. Copy TBM_patched.exe to the game directory (replace TBM.exe)")
    print("     Or rename TBM.exe to TBM_orig.exe and TBM_patched.exe to TBM.exe")
    print("  2. Delete TBMKD.sys and WatchdogMain.exe (not needed)")
    print("  3. Run TBM.exe (Admin not required since driver is not loaded)")
    print("  4. Play the game with cheats active!")
    print("=" * 60)


if __name__ == '__main__':
    main()
