@echo off

echo Note that building requires x86_64-w64-mingw32-gcc compiler and supports only Windows 64-bit.

:: ---------- Compile unpacker ----------
x86_64-w64-mingw32-gcc ^
  -I. ^
  -Icrypto/hashing ^
  -Icrypto/chacha20-poly1305 ^
  -DPOLY1305_16BIT ^
  src/unpacker.c ^
  src/injection.c ^
  crypto/chacha20-poly1305/chacha20poly1305.c ^
  crypto/chacha20-poly1305/chacha_merged.c ^
  crypto/chacha20-poly1305/poly1305-donna.c ^
  crypto/hashing/sha1.c ^
  crypto/hashing/sha224-256.c ^
  crypto/hashing/sha384-512.c ^
  crypto/hashing/usha.c ^
  crypto/hashing/hkdf.c ^
  crypto/hashing/hmac.c ^
  -o unpacker.exe ^
  -lkernel32 && (
    echo UNPACKER BUILDING SUCCESS
  ) || (
    echo UNPACKER BULDING FAILED
  )

:: ---------- Compile packer ----------
x86_64-w64-mingw32-gcc ^
  -I. ^
  -Icrypto/hashing ^
  -Icrypto/chacha20-poly1305 ^
  -DPOLY1305_16BIT ^
  src/packer.c ^
  crypto/chacha20-poly1305/chacha20poly1305.c ^
  crypto/chacha20-poly1305/chacha_merged.c ^
  crypto/chacha20-poly1305/poly1305-donna.c ^
  crypto/hashing/sha1.c ^
  crypto/hashing/sha224-256.c ^
  crypto/hashing/sha384-512.c ^
  crypto/hashing/usha.c ^
  crypto/hashing/hkdf.c ^
  crypto/hashing/hmac.c ^
  -o packer.exe ^
  -lkernel32 && (
    echo PACKER BUILDING SUCCESS
  ) || (
    echo PACKER BUILDING FAILED
  )
