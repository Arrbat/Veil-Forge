![Veil-Forge-Logo-Main](https://github.com/user-attachments/assets/b1bee8bc-b4f7-4933-a057-fbcd09b11b9b)

# Veil-Forge

## Disclaimer

**THIS PROJECT WAS NOT CREATED FOR MALWARE DEVELOPMENT.** 
It is intended solely for **legal** and/or **educational** purposes.   The author does **not** condone or support any illegal usage, including but not limited to the creation, distribution, or execution of malicious software.   **Use this tool responsibly and only in environments where you have explicit permission to do so.** 

This project is also **not guaranteed to be cryptographically and overall secure**. It was created as a demonstration of programming and reverse engineering skills. However, if this tool can help someone without violating the laws of their country — that would be appreciated.

## How It Works

In short:  
App encrypts a .exe file (dll not supported) and embed it into a precompiled unpacker (stub).  
The stub contains logic to decrypt and execute the payload at runtime.  

As a result, it becomes:
- **Impossible to statically analyze** the original `.exe` without decryption.
- **Difficult to debug and dynamically analyze**, due to runtime unpacking.


## Building

You will need the `x86_64-w64-mingw32-gcc` cross-compiler installed.

> ❌ There is no support for 32-bit systems or non-Windows operating systems.

To build everything automatically, run:

```console
./build.bat
```

## Usage

Usage:

```console
./packer.exe your.exe KEY64_IN_HEX NONCE24_IN_HEX
```

Example with test file:

```console
./packer.exe hello_world.exe  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef0123456789abcdef
```

A key and nonce must be provided by the user. Without both, the final application will not run.
Use a secure method (such as a cryptographic key generator, you may find it on the web services) to generate a 64-byte key and 24-byte nonce, in hexadecimal format. Never reuse keys or nonces across different builds.





## Technical Notes
The project uses the following algorithms:

    - AEAD ChaCha20-Poly1305
    
    - SHA-256
    
    - HKDF (HMAC-based key derivation)

    - Process Hollowing

    - Anti-debug techniques
    

Limitations:

    No support for 32-bit systems

    No Linux/macOS support

    No anti-VM or sandbox detection

    Stub does not use any obfuscation

    AV software (like Windows Defender) will almost certainly detect the final exe as a trojan

    ⚠️ Antivirus software may flag or delete the generated executable.
    F.e. Windows Defender sometimes thinks that final executable file is suspicious at least
    and describes it as the trojan and tries to delete it.

![453845503-0ab575b2-6e6f-4b7e-b56a-e1be0db81131](https://github.com/user-attachments/assets/d0080941-d532-4ca8-a13c-06eedca9511e)


# Testing Notes
Project was tested, compiled and run on Windows 11 (v.23H2), with CPU from AMD64.

If everything is okay you should see something like that (example with hello_world.exe):

```console
./build.bat

Note that building requires x86_64-w64-mingw32-gcc compiler and supports only Windows 64-bit.

Building with default warning settings.  ./build.bat WARN_ALL  for more information of building.

UNPACKER BUILDING SUCCESS

PACKER BUILDING SUCCESS


```

```console
./packer.exe hello_world.exe  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef0123456789abcdef

Checking input arguments...

Arguments are valid.

Reading input file...

Read file successfully.

Validate input file as x64 PE...

File is valid x64 PE.

Encrypting data...

Encryption ended successfully.

Copying stub template...

Copying stub template ended successfully.

HKDF: reset=0 input=0 result=0. HKDF ended as expected.

Adding encrypted resource to final.exe...

Added encrypted resources.

Packing completed successfully! Output file: final.exe.

```

```console
./final.exe
```
![image](https://github.com/user-attachments/assets/4c5cc9d9-8b1a-47ab-8dc3-f4a4c7026c61)

---

The project is completed and demonstrates skills in crypto/reverse engineering/software development.

Some questions and decisions are desctibed at Wiki page of this repository.

**If you like this all, please - star my repository and also give me feedback if you have some.**

@Arrbat
