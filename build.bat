@echo off

echo Note that building requires x86_64-w64-mingw32-gcc compiler and supports only Windows 64-bit. 
echo tests.exe will be builded with all unit tests included, so that you can check if app works as expected by running ./tests.exe . 

:: Default compiler flags
set "BASE_FLAGS=-I.. -I../headers -I../crypto/hashing -I../crypto/chacha20-poly1305 -I../src -DPOLY1305_16BIT"

:: Extra warning flags (only added if requested)
set "WARN_FLAGS="

if /I "%1"=="WARN_ALL" (
  set "WARN_FLAGS=-Wall -Wextra -Wpedantic -Wconversion"
  echo Building with ALL_WARNINGS enabled
) else (
  echo Building with default warning settings.  ./build.bat WARN_ALL  for more information of building.
)

mkdir build
cd build

:: ---------- Compile unpacker ----------
x86_64-w64-mingw32-gcc %BASE_FLAGS% %WARN_FLAGS% ^
  ../src/unpacker.c ^
  ../src/injection.c ^
  ../src/anti_debug/timing.c ^
  ../src/anti_debug/process_memory.c ^
  ../src/anti_debug/debug_flags.c ^
  ../crypto/chacha20-poly1305/chacha20poly1305.c ^
  ../crypto/chacha20-poly1305/chacha_merged.c ^
  ../crypto/chacha20-poly1305/poly1305-donna.c ^
  ../crypto/hashing/sha1.c ^
  ../crypto/hashing/sha224-256.c ^
  ../crypto/hashing/sha384-512.c ^
  ../crypto/hashing/usha.c ^
  ../crypto/hashing/hkdf.c ^
  ../crypto/hashing/hmac.c ^
  -o unpacker.exe ^
  -lkernel32 && (
    echo UNPACKER BUILDING SUCCESS
  ) || (
    echo UNPACKER BUILDING FAILED
  )

:: ---------- Compile packer ----------
x86_64-w64-mingw32-gcc %BASE_FLAGS% %WARN_FLAGS% ^
  ../src/packer.c ^
  ../crypto/chacha20-poly1305/chacha20poly1305.c ^
  ../crypto/chacha20-poly1305/chacha_merged.c ^
  ../crypto/chacha20-poly1305/poly1305-donna.c ^
  ../crypto/hashing/sha1.c ^
  ../crypto/hashing/sha224-256.c ^
  ../crypto/hashing/sha384-512.c ^
  ../crypto/hashing/usha.c ^
  ../crypto/hashing/hkdf.c ^
  ../crypto/hashing/hmac.c ^
  -o packer.exe ^
  -lkernel32 && (
    echo PACKER BUILDING SUCCESS
  ) || (
    echo PACKER BUILDING FAILED
  )

:: ---------- Compile tests ----------
x86_64-w64-mingw32-gcc %BASE_FLAGS% %WARN_FLAGS% -DTESTING_MODE ^
  ../tests/test_packer.c ^
  -o tests_packer.exe && (
    echo TESTS_PACKER BUILD SUCCESS
  ) || (
    echo TESTS_PACKER BUILD FAILED
  )

x86_64-w64-mingw32-gcc %BASE_FLAGS% %WARN_FLAGS% -DTESTING_MODE ^
  ../tests/test_unpacker.c ^
  -o tests_unpacker.exe && (
    echo TESTS_UNPACKER BUILD SUCCESS
  ) || (
    echo TESTS_UNPACKER BUILD FAILED
  )