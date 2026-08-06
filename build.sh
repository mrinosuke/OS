#!/usr/bin/env bash
# ==========================================================
# MyOS build.sh - full multi-core, full RAM (tmpfs build dir),
# builds cross-compiler once, then compiles kernel + makes .iso
#
# ব্যবহার:  chmod +x build.sh && ./build.sh
# আউটপুট:  dist/myos.iso
# ==========================================================
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$ROOT_DIR/src"
ISO_DIR="$ROOT_DIR/iso"
BUILD_DIR="$ROOT_DIR/build"
DIST_DIR="$ROOT_DIR/dist"
TOOLS_DIR="$ROOT_DIR/toolchain"

TARGET=i686-elf
BINUTILS_VER=2.42
GCC_VER=13.2.0

PREFIX="$TOOLS_DIR/$TARGET"
export PATH="$PREFIX/bin:$PATH"

CORES=$(nproc 2>/dev/null || echo 2)
MAKE_JOBS=$((CORES + 2))
LOAD_AVG=$((CORES * 2))

log()  { echo -e "\033[1;32m[build.sh]\033[0m $1"; }
err()  { echo -e "\033[1;31m[build.sh ERROR]\033[0m $1" >&2; }

log "Detected $CORES CPU cores — using -j$MAKE_JOBS for all builds."

# ---------- Step 0: sudo check ----------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        err "Needs root privileges and sudo isn't installed. Run as root."
        exit 1
    fi
fi

# ---------- Step 1: Install host dependencies ----------
log "Installing/verifying build dependencies (apt-get)..."
$SUDO apt-get update -y
$SUDO apt-get install -y \
    build-essential \
    bison \
    flex \
    libgmp3-dev \
    libmpc-dev \
    libmpfr-dev \
    texinfo \
    wget \
    curl \
    xorriso \
    grub-pc-bin \
    grub-common \
    mtools \
    nasm \
    qemu-system-x86

mkdir -p "$BUILD_DIR" "$DIST_DIR" "$TOOLS_DIR"

# ---------- Step 2: Build i686-elf cross-compiler (if missing) ----------
if [ -x "$PREFIX/bin/$TARGET-gcc" ]; then
    log "Cross-compiler $TARGET-gcc already built, skipping toolchain build."
else
    log "No cross-compiler found — building $TARGET-gcc $GCC_VER using $MAKE_JOBS parallel jobs."
    log "(First build only. This takes roughly 10-25 minutes on a multi-core machine.)"

    XSRC="$TOOLS_DIR/src"
    mkdir -p "$XSRC"
    cd "$XSRC"

    # --- binutils ---
    if [ ! -f "binutils-$BINUTILS_VER.tar.gz" ]; then
        log "Downloading binutils $BINUTILS_VER..."
        wget -q "https://ftp.gnu.org/gnu/binutils/binutils-$BINUTILS_VER.tar.gz"
    fi
    if [ ! -d "binutils-$BINUTILS_VER" ]; then
        tar -xzf "binutils-$BINUTILS_VER.tar.gz"
    fi

    mkdir -p "$XSRC/build-binutils"
    cd "$XSRC/build-binutils"
    log "Configuring binutils..."
    ../binutils-$BINUTILS_VER/configure \
        --target=$TARGET --prefix="$PREFIX" \
        --with-sysroot --disable-nls --disable-werror
    log "Compiling binutils (make -j$MAKE_JOBS)..."
    make -j"$MAKE_JOBS" -l"$LOAD_AVG"
    make install

    # --- gcc ---
    cd "$XSRC"
    if [ ! -f "gcc-$GCC_VER.tar.gz" ]; then
        log "Downloading gcc $GCC_VER..."
        wget -q "https://ftp.gnu.org/gnu/gcc/gcc-$GCC_VER/gcc-$GCC_VER.tar.gz"
    fi
    if [ ! -d "gcc-$GCC_VER" ]; then
        tar -xzf "gcc-$GCC_VER.tar.gz"
    fi

    mkdir -p "$XSRC/build-gcc"
    cd "$XSRC/build-gcc"
    log "Configuring gcc..."
    ../gcc-$GCC_VER/configure \
        --target=$TARGET --prefix="$PREFIX" \
        --disable-nls --enable-languages=c,c++ --without-headers
    log "Compiling gcc (make -j$MAKE_JOBS all-gcc all-target-libgcc) — the slow part..."
    make -j"$MAKE_JOBS" -l"$LOAD_AVG" all-gcc
    make -j"$MAKE_JOBS" -l"$LOAD_AVG" all-target-libgcc
    make install-gcc
    make install-target-libgcc

    log "Cross-compiler built at $PREFIX"
fi

CXX="$TARGET-g++"
AS="$TARGET-as"

if ! command -v "$CXX" >/dev/null 2>&1; then
    err "Cross-compiler $CXX not found on PATH after build. Aborting."
    exit 1
fi

# ---------- Step 3: Compile kernel ----------
# Note: kernel is only 9 small files, this takes ~1 second regardless
# of parallelism, so we keep this part simple and serial (safer, no
# race conditions with object file writes).
log "Compiling kernel sources with $CXX..."
cd "$ROOT_DIR"
mkdir -p "$BUILD_DIR/obj"

CXXFLAGS="-std=c++17 -ffreestanding -fno-exceptions -fno-rtti -Wall -Wextra -O2 -m32"

"$AS" "$SRC_DIR/boot.s" -o "$BUILD_DIR/obj/boot.o"
"$AS" "$SRC_DIR/gdt_flush.s" -o "$BUILD_DIR/obj/gdt_flush.o"
"$AS" "$SRC_DIR/idt_asm.s" -o "$BUILD_DIR/obj/idt_asm.o"

for f in kernel vga gdt idt keyboard kstring; do
    log "  compiling $f.cpp"
    "$CXX" $CXXFLAGS -c "$SRC_DIR/$f.cpp" -o "$BUILD_DIR/obj/$f.o"
done

# ---------- Step 4: Link kernel ----------
log "Linking kernel binary..."
"$CXX" -T "$SRC_DIR/linker.ld" -o "$BUILD_DIR/myos.bin" \
    -ffreestanding -O2 -nostdlib -m32 -no-pie \
    "$BUILD_DIR"/obj/*.o -lgcc

# Sanity check: must be multiboot-compliant
if command -v grub-file >/dev/null 2>&1; then
    if grub-file --is-x86-multiboot "$BUILD_DIR/myos.bin"; then
        log "Multiboot check: OK"
    else
        err "Multiboot check FAILED — kernel won't boot via GRUB."
        exit 1
    fi
fi

# ---------- Step 5: Build ISO ----------
log "Assembling ISO tree..."
mkdir -p "$ISO_DIR/boot/grub"
cp "$BUILD_DIR/myos.bin" "$ISO_DIR/boot/myos.bin"

log "Running grub-mkrescue..."
grub-mkrescue -o "$DIST_DIR/myos.iso" "$ISO_DIR" 2>&1 | grep -v "^xorriso" || true

if [ -f "$DIST_DIR/myos.iso" ]; then
    log "SUCCESS! ISO created at: $DIST_DIR/myos.iso"
    log ""
    log "Test it with QEMU (headless):"
    log "    qemu-system-i386 -cdrom $DIST_DIR/myos.iso -m 128 -nographic"
    log ""
    log "Or with a display:"
    log "    qemu-system-i386 -cdrom $DIST_DIR/myos.iso -m 128"
    log ""
    log "Or boot it in VirtualBox by attaching $DIST_DIR/myos.iso as an optical drive."
else
    err "ISO build failed — myos.iso not found in $DIST_DIR"
    exit 1
fi
