# PE runtime-crypter

# Disclaimer
THIS PROJECT WAS NOT CREATED FOR MALWARE DEVELOPMENT. IT IS INTENDED SOLELY FOR LEGAL AND/OR EDUCATIONAL PURPOSES. THE AUTHOR DOES NOT CONDONE OR SUPPORT ANY ILLEGAL USAGE, INCLUDING BUT NOT LIMITED TO THE CREATION, DISTRIBUTION, OR EXECUTION OF MALICIOUS SOFTWARE. USE THIS TOOL RESPONSIBLY AND ONLY IN ENVIRONMENTS WHERE YOU HAVE EXPLICIT PERMISSION TO DO SO. 

# How it works?
Shortly - we encrypt our PE (f.e. .exe file), then we put it into our pre-compiled stub, which has algorithm to both decrypting and running some code from .exe . So in the end it is immposible to find out what your.exe does by using static analysis and hard to deal with by debugging it and by using dynamic analysis.

#### Building
```
x86_64-w64-mingw32-gcc stub.c salsa20.c -o stub.exe -lkernel32 && x86_64-w64-mingw32-gcc builder.c salsa20.c -o builder.exe -lkernel32 
```

#### Using
```
./builder.exe your.exe KEY64_IN_HEX_FORMAT NONCE16_IN_HEX_FORMAT 
```

# Security Notes

Here salsa20 is custom implementation of salsa20 **without security** against side-channel attacks, repeatable nonces or keys.

Key and nonce **MUST BE** provided by user. Use some web services to generate secure key and nonce.

There is no obfuscation of stub yet.

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

7) Add integrity check before injection to make sure that PE headers were not changed

8) Make simple anti-debbuger

9) Make anti-vm(?) or auto-exit if there is processes like ida.exe , x64dbg.exe etc

10) Make Reflective Loader

11) Hide imports

First of all to do: (1-partly-completed), (2-completed), (3), (5), (7), (8)