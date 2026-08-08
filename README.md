# PenLock

A Windows USB security tool: install it onto a pendrive, and it encrypts
the drive's contents behind a password, with four selectable security
levels (including two that will delete data after too many wrong
password attempts). Built as a Ventoy-style two-partition layout — one
visible data partition, one hidden partition holding PenLock itself plus
the vault metadata.

## Before anything else: what's tested and what isn't

This project was built in a Linux sandbox with **no access to a Windows
machine, no mingw-w64 cross-compiler, and no real USB hardware**. That
split the codebase into two very different confidence levels:

**Fully implemented and unit-tested (passing, verified against
independent ground truth like OpenSSL and Python's hashlib):**
- SHA-256, AES-256-CBC, PBKDF2-HMAC-SHA256 (`src/crypto/`)
- Vault metadata format, serialization (`src/vault/vault_format.h`)
- Master-key wrapping with password / recovery key (`src/vault/key_wrap.h`)
- Per-file lock/unlock transform logic (`src/vault/file_vault.h`)
- Security-level decision logic — Normal/Standard/High/Ultra attempt
  tracking, lockout timing, wipe triggers (`src/vault/lock_manager.h`)

Run `./test/test_*` (already built once during development) or rebuild
with e.g. `g++ -std=c++17 -O2 -o test/test_aes test/test_aes.cpp && ./test/test_aes`
to re-verify any of these yourself — they need nothing but a normal Linux
or Windows C++ compiler, no Windows SDK required.

**Written carefully, but NOT compiled or run anywhere (no Windows/mingw
available in the build environment) — treat first real build as a
debugging pass:**
- USB drive detection (`src/usb/usb_detect.h`)
- diskpart-based partitioning (`src/usb/partition.h`)
- Wipe/format operations (`src/usb/wipe.h`)
- The entire GUI (`src/gui/`) and `src/main.cpp`

This isn't a hedge to lower expectations for no reason — it's the honest
state of things, and it tells you where to focus when something doesn't
work: the crypto/logic core is trustworthy, the Windows-facing plumbing
around it needs real hardware testing before you rely on it.

## Building

```bash
chmod +x build.sh
./build.sh
```

Run this **on Ubuntu (or another apt-based distro) with internet
access** — the opposite of the sandbox this was written in. It will:

1. Install `mingw-w64` via apt if it's not already present (asks for
   your sudo password).
2. Make sure the **POSIX threading variant** of mingw-w64 is selected —
   PenLock uses `std::thread`, which mingw's default "win32" threading
   model doesn't support. The script checks this with a throwaway
   compile and tells you exactly what to run if it needs manual
   adjustment (`sudo update-alternatives --config x86_64-w64-mingw32-g++`).
3. Compile using all your CPU cores in parallel.
4. Link statically so `PenLock.exe` needs **no extra DLLs** — if static
   linking isn't available on your system for some reason, it
   automatically falls back to a dynamic build and copies the 3 runtime
   DLLs it needs into the output folder instead.
5. Put the result in `./PenLock/`.

Copy that `PenLock/` folder to a Windows machine and run `PenLock.exe`.

## How to test safely

**Use a spare/scratch USB drive with nothing important on it.** Several
features are destructive by design (that's the point of High/Ultra
security), and this is the first real-world run of code that's only
been reasoned about, not executed.

Suggested test order:
1. Plug in the scratch drive, launch PenLock, confirm it shows up in the
   drive list and NVMe/internal drives do not.
2. Install with **Normal** security first. Confirm: partitioning
   succeeds, the drive shows as locked/empty after re-plugging, the
   correct password unlocks it and files appear, wrong passwords are
   accepted without penalty.
3. Add a few real test files, lock, unlock, verify content is byte-for-
   byte intact (this exact logic is unit-tested already, so this step is
   really about the partition/GUI plumbing around it, not the crypto).
4. Try the recovery key path deliberately (use "Forgot password").
5. Only after Normal works end-to-end, test Standard (verify the 10-
   minute lockout), then High and Ultra **on a drive you're fully
   prepared to lose data on**, to confirm the wipe actually triggers at
   the right attempt count and actually completes.
6. Test unplugging without using "Lock Now" first, to see the
   best-effort removal-detection warning (see Known gaps below — this
   does NOT re-encrypt anything after the fact, it only warns).

## Architecture

```
src/
  crypto/     sha256.h, aes.h, pbkdf2.h, random.h   — portable, tested
  vault/      vault_format.h, key_wrap.h,
              file_vault.h, lock_manager.h           — portable, tested
  usb/        usb_detect.h, partition.h, wipe.h       — Windows-only, untested
  gui/        theme.h, app_state.h,
              main_window.h/.cpp, tray.h              — Windows-only, untested
  main.cpp                                            — Windows-only, untested
resources/    app.ico, app.rc
test/         standalone unit tests for the portable layer
```

**Two-partition layout** (created via scripted `diskpart`, not manual
MBR/GPT byte-twiddling — the "boring and reliable" choice):
- Partition 1 ("PenLock"), exFAT, most of the capacity — the visible
  data partition. Real files when unlocked; encrypted `.plk` siblings
  when locked.
- Partition 2 ("PLSYS"), NTFS, ~64 MB — holds `penlock.dat` (vault
  metadata) and a copy of `PenLock.exe` itself. Never assigned a drive
  letter except briefly when PenLock itself needs to read/write it, so
  Explorer doesn't show it — the same trick Ventoy uses for its own
  hidden system partition.

**Important honesty note on "hidden":** this means *no drive letter, so
File Explorer won't show it during normal browsing*. It is still fully
visible to Disk Management, `diskpart list volume`, and any forensic or
recovery tool. That's a real but limited layer of obscurity, not
hardware-grade concealment — genuinely hiding a partition from every
tool would need a kernel-mode filter driver, which needs Microsoft
driver signing and is a much bigger project than this.

**Per-file encryption, not a mounted virtual volume:** locking transforms
`document.pdf` into `document.pdf.plk` (16-byte random IV + AES-256-CBC
ciphertext) in place, and unlocking reverses it. This avoids needing a
kernel driver (VeraCrypt/BitLocker-style mounting needs one), at the
cost of: while unlocked, files are genuine plaintext sitting on the
partition — protection is against the drive being read *while locked*
(lost, stolen, or plugged into another PC without the password), not
against someone with access to an already-unlocked drive.

**Security levels** (`src/vault/lock_manager.h`, fully unit-tested):
- **Normal** — unlimited attempts, no penalty.
- **Standard** — 5 wrong attempts → 10-minute lockout (persisted across
  app restarts via the vault metadata, not just in-memory).
- **High** — 3 wrong attempts → data partition is quick-formatted.
  PenLock itself (partition 2) survives; the same password keeps working
  afterward for future use.
- **Ultra** — 1 wrong attempt → quick format, then the entire free space
  is overwritten with a growing filler file (`rm.txt`) until the disk
  reports full, then that file is deleted — an anti-forensic pass so
  deleted file remnants aren't trivially recoverable.

**Recovery key**: generated once at install time (38-character, shown
once, never stored anywhere but derived-and-compared), wraps an
independent copy of the same master key. Bypasses Standard's lockout.
Does **not** currently get regenerated when you change your password —
see Known gaps.

## Known gaps (real limitations, not hidden)

- **Auto-lock on eject is best-effort, not guaranteed.** PenLock listens
  for `WM_DEVICECHANGE` / `DBT_DEVICEREMOVECOMPLETE`, which fires
  *after* the drive has already disconnected — by then it's too late to
  write a re-encrypted copy back. What it does do: notice the drive
  vanished while unlocked, clear the key from memory, and warn you that
  files may still be plaintext on it. **The safe habit is to click "Lock
  Now" before physically removing the drive.** A complete fix would
  register for `DBT_DEVICEQUERYREMOVE` on the volume handle (fires
  *before* Safe-Eject completes) and lock synchronously in that handler
  — not implemented here, flagged as the natural next step.
- **Recovery key doesn't rotate.** Changing your password re-wraps the
  master key under the new password, but the original recovery key
  still works too (it wraps the same master key independently). If that
  matters to you, treat a password change as a reason to also note that
  the old recovery key remains valid, or extend `handle_change_password_command`
  to regenerate it (the pieces — `generate_recovery_key_string()`,
  `wrap_master_key()` — are already there to compose).
- **diskpart output parsing is a heuristic.** Success/failure detection
  in `partition.h`/`wipe.h` greps the captured output for a few known
  error phrases. This should be re-checked against real diskpart output
  on the actual Windows version you're targeting — locale/language
  differences in Windows could change diskpart's message text.
- **No DPI awareness.** Control positions are fixed pixel coordinates.
  On a high-DPI display this may look cramped; adding a manifest with
  `PerMonitorV2` DPI awareness plus scaling the layout is future work.
- **UAC decline has no retry loop.** If the user dismisses the elevation
  prompt, PenLock shows a message and exits rather than offering to
  re-prompt.
- **Only ASCII/Unicode passwords via UTF-8 were exercised in testing**
  (the conversion itself — `WideCharToMultiByte` — is correct and
  general, but the end-to-end "type a Bengali password, unlock with it
  later" path hasn't been run for real since it needs the GUI).

None of these are silent — each one is also called out as a comment at
its exact location in the code, so "known gap" isn't just a README claim
divorced from the implementation.

## Security model summary

- Files are protected by AES-256-CBC under a random master key.
- The master key itself is never derived from your password directly —
  your password (via PBKDF2-HMAC-SHA256, 300,000 iterations) only wraps
  (encrypts) a copy of it. This is why changing your password doesn't
  require re-encrypting every file, and why both a password and an
  independent recovery key can unlock the same data.
- Wrong-password detection relies on PKCS7 padding validation during
  AES-CBC decryption of the wrapped key — this is a standard technique,
  verified in `test/test_key_wrap.cpp`.
