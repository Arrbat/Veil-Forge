# Simple PE runtime-crypter

# How it works?
Shortly - we encrypt our PE (f.e. .exe file), then we put it into our pre-compiled stub, which has algorithm to both decrypting and running some code from .exe . So in the end it is immposible to find out what your.exe does by using static analysis and hard to deal with by debugging it and by using dynamic analysis.

#### Building
```
x86_64-w64-mingw32-gcc stub.c salsa20.c -o stub.exe -lkernel32 && x86_64-w64-mingw32-gcc builder.c salsa20.c -o builder.exe -lkernel32 
```

#### Using
```
./builder.exe your.exe  
```


# Security Notes
Here salsa20 is custom implementation of salsa20 without security against side-channel attacks, repeatable nonces or keys.
Key and nonce are both constant.
There is no obfuscation of stub. 

# Possible "To improve"

1) Make salsa20 more safe (probably to use existing salsa20 code)
2) Make it possible to use your key and nonce for encrypting/decrypting, like
```
./builder.exe pathto.exe key nonce
```
3) Make auto-building of project, without need to compile two files
4) Implement obfuscation (custom or by using existing tools?)
5) Improve code structure, cause now it is little bit too complex
6) Make support of 32bit systems 