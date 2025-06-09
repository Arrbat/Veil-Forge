# PE runtime-crypter

# Disclaimer
THIS PROJECT WAS NOT CREATED FOR MALWARE DEVELOPMENT. IT IS INTENDED SOLELY FOR LEGAL AND/OR EDUCATIONAL PURPOSES. THE AUTHOR DOES NOT CONDONE OR SUPPORT ANY ILLEGAL USAGE, INCLUDING BUT NOT LIMITED TO THE CREATION, DISTRIBUTION, OR EXECUTION OF MALICIOUS SOFTWARE. USE THIS TOOL RESPONSIBLY AND ONLY IN ENVIRONMENTS WHERE YOU HAVE EXPLICIT PERMISSION TO DO SO. 

Also, the project is not absolutely secure in terms of cryptographic strength. The project as a whole was created as a demonstration of skills, knowledge in reverse engineering and programming, but I would be grateful if this project can help someone. 

# How it works?
Shortly - we encrypt our PE (f.e. .exe file), then we put it into our pre-compiled stub, which has algorithm to both decrypting and running some code from .exe . So in the end it is immposible to find out what your.exe does by using static analysis and hard to  debug it and analyse dynamically.

#### Building
```
./build.bat
```

#### Using
```
./builder.exe your.exe KEY64_IN_HEX_FORMAT NONCE24_IN_HEX_FORMAT 
```

f.e. (key and nonce are not randomized):
```
./builder.exe tests/test.exe 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef0123456789abcdef
```

# Security Notes

Project uses ChaCha20 algorithm for both ecryption/decryption and obfuscation/deobfuscation, SHA256 for hashing.

Key and nonce **MUST BE** provided by user; without key or nonce app will not even start. Use some web services to generate secure key and nonce. Also, **never** use the same key or/and nonce that you have used previously in another or the same application.

It may be noted that there is very very basic anti-debugger technique.

Finally, stub uses process hollowing techniquem which is effective.

# Testing Notes
Project was tested, compiled and run on Windows 11 (v.23H2), with CPU from AMD64.

If everything is okay you should see something like that (example with test.exe):

```
./build.bat                    

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

PS C:\Users\home\Documents\PROJECT\runtime-crypter> ./final.exe   

Hello World

ENCRYPTEEEEEEEEEEEEEEEEEEEEEEED

PS C:\Users\home\Documents\PROJECT\runtime-crypter> 

```
---

If you like this all, please - star my repository and also give me feedback if you have some.

@Arrbat
