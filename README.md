![Veil-Forge-Logo-Main](https://github.com/user-attachments/assets/b1bee8bc-b4f7-4933-a057-fbcd09b11b9b)




# Veil-Forge

## Disclaimer

**THIS PROJECT WAS NOT CREATED FOR MALWARE DEVELOPMENT.** 
It is intended solely for **legal** and/or **educational** purposes.   The author does **not** condone or support any illegal usage, including but not limited to the creation, distribution, or execution of malicious software.   **Use this tool responsibly and only in environments where you have explicit permission to do so.** 

This project is also **not guaranteed to be cryptographically secure**. It was created as a demonstration of programming and reverse engineering skills. However, if this tool can help someone without violating the laws of their country — that would be appreciated.

## How It Works

In short:  
App encrypts a PE file (e.g. `.exe`) and embed it into a precompiled stub.  
The stub contains logic to decrypt and execute the payload at runtime.  

As a result, it becomes:
- **Impossible to statically analyze** the original `.exe` without decryption.
- **Difficult to debug and dynamically analyze**, due to runtime unpacking.


## Building

You will need the `x86_64-w64-mingw32-gcc` cross-compiler installed.

> ❌ There is no support for 32-bit systems or non-Windows operating systems.

To build the stub, run:

```bash
./build.bat
```

## Usage

Usage:

```
./builder.exe your.exe KEY64_IN_HEX NONCE24_IN_HEX
```

Example with test file:

```
./builder.exe tests/test.exe  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef0123456789abcdef
```

A key and nonce must be provided by the user. Without both, the final application will not run.
Use a secure method (such as a cryptographic key generator, you may find it on the web services) to generate a 64-byte key and 24-byte nonce, in hexadecimal format. Never reuse keys or nonces across different builds.





## Technical Notes
The project uses the following algorithms:

    - AEAD ChaCha20-Poly1305
    
    - SHA-256
    
    - HKDF (HMAC-based key derivation)
    

Limitations:

    No support for 32-bit systems

    No Linux/macOS support

    No anti-VM or sandbox detection

    Stub does not use any obfuscation

    Contains only a single-line anti-debugging technique

    AV software (like Windows Defender) will almost certainly detect the stub as a trojan

    ⚠️ Antivirus software may flag or delete the generated executable.
    You must manually allow the file if testing in Windows. 

![453845503-0ab575b2-6e6f-4b7e-b56a-e1be0db81131](https://github.com/user-attachments/assets/d0080941-d532-4ca8-a13c-06eedca9511e)







# Testing Notes
Project was tested, compiled and run on Windows 11 (v.23H2), with CPU from AMD64.

If everything is okay you should see something like that (example with test.exe):

```
./build.bat                    
```
```
./builder.exe tests/test.exe 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef0123456789abcdef

Checking input arguments...

Arguments are valid.

Reading input file...

Read file succesfully.

Validate input file as x64 PE...

File is valid x64 PE.

Encrypting data...

Encryption ended successfully

Copying stub template...

Copying stub template ended succesfully

Adding encrypted resource to final.exe...

Added encrypted resources.

Packing completed successfully! Output file: final.exe
```
```
> ./final.exe   

Hello World

ENCRYPTEEEEEEEEEEEEEEEEEEEEEEED

```
---

This application is planned as a solution to protect your software using advanced technologies such as polymorphism, anti-debugging mechanisms, anti-VM  and more.

The project is still under development and contributions are very welcome.

A comprehensive Wiki and documentation will also be added to explain the reasoning behind specific design choices, as well as to provide in-depth technical details for those interested in how everything works under the hood.

**If you like this all, please - star my repository and also give me feedback if you have some.**

@Arrbat
