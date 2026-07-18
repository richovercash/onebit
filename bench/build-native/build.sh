#!/bin/bash
# Build the native on-device proving benchmark for aarch64-android.
# Prereqs: rustup target add aarch64-linux-android; Android NDK r27c;
#          a phone plugged in (to pull its platform libc++/libc for linking).
set -e
NDK=${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to android-ndk-r27c}
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
HERE=$(dirname "$(readlink -f "$0")")
LINKDIR=$HERE/platform-libs
mkdir -p "$LINKDIR"
# Pull the phone's platform libs (upstream libc++ uses __1, matching Aztec's bb).
for lib in libc++.so libc.so libm.so libdl.so; do
  [ -f "$LINKDIR/$lib" ] || adb pull /system/lib64/$lib "$LINKDIR/$lib"
done
cp "$LINKDIR/libc++.so" "$LINKDIR/libstdc++.so"
# Shim: glibc-isms bionic lacks + libc++ base-class symbols.
"$TC/aarch64-linux-android34-clang" -c -O2 -fPIC "$HERE/cxxstub.c" -o "$HERE/cxxstub.o"
export CC_aarch64_linux_android=$TC/aarch64-linux-android34-clang
export CXX_aarch64_linux_android=$TC/aarch64-linux-android34-clang++
export AR_aarch64_linux_android=$TC/llvm-ar
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$TC/aarch64-linux-android34-clang
export ANDROID_API_LEVEL=34
export RUSTFLAGS="-L native=$LINKDIR -C link-arg=$HERE/cxxstub.o -C link-arg=-Wl,--unresolved-symbols=ignore-all"
cd "$HERE/../noir-rs"
cargo build -p bench_native --target aarch64-linux-android --release
echo "binary: $(pwd)/target/aarch64-linux-android/release/bench_native"
