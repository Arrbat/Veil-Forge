# PE runtime-crypter

# Disclaimer
THIS PROJECT WAS NOT CREATED FOR MALWARE DEVELOPMENT. IT IS INTENDED SOLELY FOR LEGAL AND/OR EDUCATIONAL PURPOSES. THE AUTHOR DOES NOT CONDONE OR SUPPORT ANY ILLEGAL USAGE, INCLUDING BUT NOT LIMITED TO THE CREATION, DISTRIBUTION, OR EXECUTION OF MALICIOUS SOFTWARE. USE THIS TOOL RESPONSIBLY AND ONLY IN ENVIRONMENTS WHERE YOU HAVE EXPLICIT PERMISSION TO DO SO. 

Also, the project is not absolutely secure in terms of cryptographic strength. The project as a whole was created as a demonstration of skills, knowledge in reverse engineering and programming, but I would be grateful if this project can help someone. 

# How it works?
Shortly - we encrypt our PE (f.e. .exe file), then we put it into our pre-compiled stub, which has algorithm to both decrypting and running some code from .exe . So in the end it is immposible to find out what your.exe does by using static analysis and hard to  debug it and analyse dynamically.

#### Building
```
x86_64-w64-mingw32-gcc stub.c salsa20.c -o stub.exe -lkernel32 && x86_64-w64-mingw32-gcc builder.c salsa20.c -o builder.exe -lkernel32 
```

#### Using
```
./builder.exe your.exe KEY64_IN_HEX_FORMAT NONCE16_IN_HEX_FORMAT 
```

f.e. (key and nonce are not randomized):
```
./builder.exe test.exe 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF AABBCCDDEEFF1122
```

# Security Notes

Here salsa20 is custom implementation of salsa20, so it might be insecure, specially against side-channel attacks.

Key and nonce **MUST BE** provided by user; without key or nonce app will not even start. Use some web services to generate secure key and nonce. Also, **never** use the same key or/and nonce that you have used previously in another or the same application.

Counter in salsa20 is constant. With secure key and nonce this is not a very big problem, but is makes algorithm more predictable

This project uses LCG generator which is not secure, but for simplicity I use that one.

Also there is SHA1 algorithm, which is worse then SHA256 f.e. . But SHA1 needs much less code and is simpler for understanding.

There is modified XOR (de)obfuscation algorithm, which use result of LCG (and LCG uses hash of payload as a seed).

It may be noted that there is very very basic anti-debugger technique.

Finally, stub uses process hollowing techniquem which is effective.

# Testing Notes
Project was tested, compiled and run on Windows 11 (v.23H2), with CPU from AMD64.

If everything is okay you should see something like that (example with test.exe):

```
PS C:\Users\home\Documents\PROJECT\runtime-crypter> **x86_64-w64-mingw32-gcc stub.c salsa20.c -o stub.exe -lkernel32**

PS C:\Users\home\Documents\PROJECT\runtime-crypter> **x86_64-w64-mingw32-gcc builder.c salsa20.c -o builder.exe -lkernel32**

PS C:\Users\home\Documents\PROJECT\runtime-crypter> **./builder.exe test.exe 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF AABBCCDDEEFF1122**

Checking input arguments... Success

Reading input file... Success

Validate input file as x64 PE... Success

Encrypting data... Success

Copying stub template... Success

Adding encrypted resource to final.exe... Success


Packing completed successfully! Output file: final.exe

Press any key to continue . . . 

PS C:\Users\home\Documents\PROJECT\runtime-crypter> ./final.exe 

Hello World

ENCRYPTEEEEEEEEEEEEEEEEEEEEEEED

PS C:\Users\home\Documents\PROJECT\runtime-crypter>
```

Also I tested it with larger game (Mindustry, java programming language). Here I renamed final.exe into Mindustry.exe , because it expects some configs etc. and with another name it does not work.

```
PS C:\Users\home\Documents\PROJECT\runtime-crypter> ./builder.exe Mindustry.exe 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF AABBCCDDEEFF1122

*Here is success message; after that i renamed final.exe into expected Mindustry.exe*

PS C:\Users\home\Documents\PROJECT\runtime-crypter> ./Mindustry.exe

[I] [Core] Initialized SDL v2.0.20

[I] [Audio] Initialized SoLoud 202409 using MiniAudio at 44100hz / 441 samples / 2 channels

[I] [GL] Version: OpenGL 4.6.0 / ATI Technologies Inc. / AMD Radeon RX 7600S

[I] [GL] Max texture size: 16384

[I] [GL] Using OpenGL 3 context.

[I] [JAVA] Version: 23

[I] [RAM] Available: 3.9 GB

[I] [Mindustry] Version: 149

[I] Total time to load: 2353ms

[I] Fetched 49 community servers.
```

GUI was launched and it did not crash. 

---

If you like this all, please - star my repository and also give me feedback if you have some.

@Arrbat
