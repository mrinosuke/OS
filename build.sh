#!/usr/bin/env bash
# build.sh - Builds PenLock.exe from source on Ubuntu (or any apt-based
# distro), cross-compiling for Windows with mingw-w64.
#
# What this script does, step by step:
#   1. Checks whether mingw-w64 is installed; if not, installs it via apt
#      (needs sudo — you'll be prompted for your password).
#   2. Makes sure the POSIX threading variant of mingw-w64 is selected,
#      because PenLock uses std::thread, which mingw-w64's default
#      "win32" threading model does not support.
#   3. Compiles every .cpp file under src/, using all available CPU cores
#      (`make -jN` / parallel g++ invocation) for speed.
#   4. Links statically where possible, so the resulting PenLock.exe does
#      NOT need any extra DLLs shipped alongside it. If static linking
#      isn't available for some reason, it automatically falls back to a
#      dynamic build and copies the 3 runtime DLLs it needs into the
#      output folder instead.
#   5. Puts the final result in ./PenLock/ (PenLock.exe, and DLLs only if
#      the fallback path was used).
#
# Run it from the project root:
#   chmod +x build.sh && ./build.sh
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
RES_DIR="$PROJECT_ROOT/resources"
OUT_DIR="$PROJECT_ROOT/PenLock"
BUILD_DIR="$PROJECT_ROOT/.build"

echo "=== PenLock build ==="
echo "Project root: $PROJECT_ROOT"

# ---------------------------------------------------------------------
# 1. Make sure mingw-w64 is installed.
# ---------------------------------------------------------------------
CXX="x86_64-w64-mingw32-g++"
WINDRES="x86_64-w64-mingw32-windres"

if ! command -v "$CXX" >/dev/null 2>&1; then
    echo "-- mingw-w64 not found, installing (requires sudo)..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y mingw-w64 mingw-w64-tools
    else
        echo "ERROR: apt-get not found. This script currently only auto-installs"
        echo "on Debian/Ubuntu-based systems. Please install a mingw-w64 cross"
        echo "toolchain manually and re-run this script."
        exit 1
    fi
else
    echo "-- mingw-w64 already installed: $(command -v "$CXX")"
fi

# ---------------------------------------------------------------------
# 2. Ensure the POSIX threading model variant is selected (needed for
#    std::thread). Debian/Ubuntu's mingw-w64 package ships both "win32"
#    and "posix" variants selectable via update-alternatives.
# ---------------------------------------------------------------------
if command -v update-alternatives >/dev/null 2>&1; then
    if update-alternatives --list x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
        POSIX_GXX="$(update-alternatives --list x86_64-w64-mingw32-g++ 2>/dev/null | grep posix || true)"
        if [ -n "$POSIX_GXX" ]; then
            echo "-- Selecting POSIX threading model for mingw-w64 (needed for std::thread)..."
            sudo update-alternatives --set x86_64-w64-mingw32-g++ "$POSIX_GXX" || true
            POSIX_GCC="$(update-alternatives --list x86_64-w64-mingw32-gcc 2>/dev/null | grep posix || true)"
            [ -n "$POSIX_GCC" ] && sudo update-alternatives --set x86_64-w64-mingw32-gcc "$POSIX_GCC" || true
        fi
    fi
fi

# Verify std::thread actually works with a tiny throwaway test, so we
# fail fast with a clear message instead of a wall of linker errors later.
echo "-- Verifying std::thread support in the selected toolchain..."
TMP_TEST_DIR="$(mktemp -d)"
cat > "$TMP_TEST_DIR/t.cpp" << 'EOF'
#include <thread>
int main() { std::thread t([]{}); t.join(); return 0; }
EOF
if ! "$CXX" -std=c++17 -O2 "$TMP_TEST_DIR/t.cpp" -o "$TMP_TEST_DIR/t.exe" -static -static-libgcc -static-libstdc++ 2>"$TMP_TEST_DIR/err.log"; then
    echo "WARNING: std::thread failed to link with the current mingw-w64 variant."
    echo "         This usually means the 'win32' threading model is active instead"
    echo "         of 'posix'. See the error below; you may need to run:"
    echo "           sudo update-alternatives --config x86_64-w64-mingw32-g++"
    echo "         and pick the '-posix' option manually, then re-run build.sh."
    echo "--- linker output ---"
    cat "$TMP_TEST_DIR/err.log"
    rm -rf "$TMP_TEST_DIR"
    exit 1
fi
rm -rf "$TMP_TEST_DIR"
echo "-- std::thread OK."

# ---------------------------------------------------------------------
# 3. Compile.
# ---------------------------------------------------------------------
mkdir -p "$BUILD_DIR" "$OUT_DIR"
JOBS="$(nproc 2>/dev/null || echo 4)"
echo "-- Using $JOBS parallel jobs (full CPU) for compilation."

CXXFLAGS="-std=c++17 -O2 -Wall -Wno-unused-parameter -municode -DUNICODE -D_UNICODE -I$SRC_DIR"
LIBS="-lcomctl32 -lshell32 -lole32 -luuid -lbcrypt -lsetupapi -lgdi32 -luser32 -lkernel32 -ladvapi32 -lversion -lwinmm"

# Resource file (icon + version info)
echo "-- Compiling resources..."
"$WINDRES" -I "$RES_DIR" "$RES_DIR/app.rc" -O coff -o "$BUILD_DIR/app_res.o"

# Compile each .cpp to a .o in parallel, then link. Only main.cpp and
# src/gui/main_window.cpp currently contain non-header-only code; other
# logic lives in headers included by these. Keeping the .cpp list
# explicit (rather than a glob) makes the build predictable if more
# .cpp files are added later.
CPP_FILES=(
    "$SRC_DIR/main.cpp"
    "$SRC_DIR/gui/main_window.cpp"
)

OBJ_FILES=()
PIDS=()
for f in "${CPP_FILES[@]}"; do
    obj="$BUILD_DIR/$(basename "${f%.cpp}").o"
    OBJ_FILES+=("$obj")
    echo "-- Compiling $(basename "$f")..."
    "$CXX" $CXXFLAGS -c "$f" -o "$obj" &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do
    wait "$pid"
done

# ---------------------------------------------------------------------
# 4. Link. Try fully static first (no DLLs needed at all); fall back to
#    dynamic + bundled runtime DLLs if that's not possible on this
#    system's mingw-w64 installation.
# ---------------------------------------------------------------------
EXE_OUT="$OUT_DIR/PenLock.exe"
echo "-- Linking (static)..."
if "$CXX" $CXXFLAGS -mwindows "${OBJ_FILES[@]}" "$BUILD_DIR/app_res.o" \
        -o "$EXE_OUT" $LIBS -static -static-libgcc -static-libstdc++ -lpthread 2>"$BUILD_DIR/link_static.log"; then
    echo "-- Static link succeeded. PenLock.exe needs no extra DLLs."
else
    echo "-- Static link failed, falling back to dynamic link + bundled DLLs."
    cat "$BUILD_DIR/link_static.log"
    "$CXX" $CXXFLAGS -mwindows "${OBJ_FILES[@]}" "$BUILD_DIR/app_res.o" \
        -o "$EXE_OUT" $LIBS -lpthread

    MINGW_BIN_DIR="$(dirname "$(command -v "$CXX")")"
    MINGW_LIB_DIR="$(x86_64-w64-mingw32-g++ -print-sysroot 2>/dev/null || echo "")/mingw/bin"
    for candidate_dir in "$MINGW_BIN_DIR" "$MINGW_LIB_DIR" "/usr/x86_64-w64-mingw32/bin" "/usr/lib/gcc/x86_64-w64-mingw32"/*; do
        [ -d "$candidate_dir" ] || continue
        for dll in libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll; do
            found="$(find "$candidate_dir" -maxdepth 2 -name "$dll" 2>/dev/null | head -1)"
            if [ -n "$found" ] && [ ! -f "$OUT_DIR/$dll" ]; then
                cp "$found" "$OUT_DIR/"
                echo "   copied $dll"
            fi
        done
    done
fi

rm -rf "$BUILD_DIR"

echo ""
echo "=== Build complete ==="
echo "Output: $OUT_DIR/"
ls -la "$OUT_DIR"
echo ""
echo "Copy the PenLock/ folder to a Windows machine and run PenLock.exe."
echo "It will ask for Administrator permission (needed to manage USB"
echo "partitions) — this is expected."
