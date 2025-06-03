# runtime-crypter
Simple PE runtime-crypter


# How it works?
App takes a path to your .exe (payload) as the first argument and does following steps:
1) reads payload pointed by PATH
2) encrypts it by using __ algorithm
3) generates new C-file "stub + encrypted payload" and compiles it into completed .exe. So that in your PATH will be generated new wrapped binary (.exe). 

# step-by-step development
1) Set environment. Compiler is x86_64-w64-mingw32-gcc. 
Also build and locate in Project Directory test.exe 

2) builder.c
takes one argument - string path
opens and reads file as bytes array
takes the key and with algoritm in the loop encrypts every byte
saves encrypted bytes in temp_payload.h

3) stub.c
takes externs from temp_payload.h
allocates memory for exec
decrypts bytes
run exec

4) builder.c 
after written temp payload and saved stub copy - 
calls compiler which builds everything and gives .exe


salsa20 is custom implementation of salsa20 without security against side-channel attacks, repeatable nonces or keys. 