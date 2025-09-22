```
       __   _______ .__   __. .__   __.  __   _______  _______ .______      
      |  | |   ____||  \ |  | |  \ |  | |  | |   ____||   ____||   _  \     
      |  | |  |__   |   \|  | |   \|  | |  | |  |__   |  |__   |  |_)  |    
.--.  |  | |   __|  |  . `  | |  . `  | |  | |   __|  |   __|  |      /     
|  `--'  | |  |____ |  |\   | |  |\   | |  | |  |     |  |____ |  |\  \----.
 \______/  |_______||__| \__| |__| \__| |__| |__|     |_______|| _| `._____|
                                                                            
The most advanced password recovery 
For all version of .kdbx (KeePass 2.X) by: @byt3n33dl3
								  version: 1.1.0

```

Jennifer du' Casse is the most Advanced KeePass .kdbx cracking software. Support cracking KDBX3 (KeePass 2.x) and KDBX4. Designed to handle all versions of KeePass database files (.kdbx), including the newer 2.36+ versions that use the KDBX4 format.

Please do not use in military or secret service organizations, or for illegal purposes. (This is the wish of the author and non-binding. Many people working in these organizations do not care for laws and ethics anyways. You are not one of the "good" ones if you ignore this.)

## Database Example:

KeePass Version 2.X

```
┌──(kali㉿kali)-[~]
└─$ file recovery.kdbx 
recovery.kdbx: Keepass password database 2.x KDBX
```

```
┌──(kali㉿kali)-[~]
└─$ hexdump -C -n 16 recovery.kdbx 
00000000  03 d9 a2 9a 67 fb 4b b5  00 00 04 00 02 10 00 00  |....g.K.........|
00000010
```

Signature:

```
┌──(kali㉿kali)-[~]
└─$ xxd -l 32 recovery.kdbx 
00000000: 03d9 a29a 67fb 4bb5 0000 0400 0210 0000  ....g.K.........
00000010: 0031 c1f2 e6bf 7143 50be 5805 216a fc5a  .1....qCP.X.!j.Z
```

## Jennifer Recovery with Wordlists:

```
┌──(kali㉿kali)-[~
└─$ jennifer recovery.kdbx /usr/share/wordlists/rockyou.txt 
       __   _______ .__   __. .__   __.  __   _______  _______ .______      
      |  | |   ____||  \ |  | |  \ |  | |  | |   ____||   ____||   _  \     
      |  | |  |__   |   \|  | |   \|  | |  | |  |__   |  |__   |  |_)  |    
.--.  |  | |   __|  |  . `  | |  . `  | |  | |   __|  |   __|  |      /     
|  `--'  | |  |____ |  |\   | |  |\   | |  | |  |     |  |____ |  |\  \----.
 \______/  |_______||__| \__| |__| \__| |__| |__|     |_______|| _| `._____|
                                                                            
The most advanced password recovery 
For all version of .kdbx (KeePass 2.X) by: @byt3n33dl3
                                                                  version: 1.1.0
[+] KeePass database detected (version 4)
[+] Using AES-KDF key derivation
[+] Starting password cracking with 14344400 passwords

[+] Password found: liverpool
```

No longer than 26 Minutes,

With verbosity:

```
┌──(kali㉿kali)-[~]
└─$ jennifer recovery.kdbx /usr/share/wordlists/rockyou.txt -v
       __   _______ .__   __. .__   __.  __   _______  _______ .______      
      |  | |   ____||  \ |  | |  \ |  | |  | |   ____||   ____||   _  \     
      |  | |  |__   |   \|  | |   \|  | |  | |  |__   |  |__   |  |_)  |    
.--.  |  | |   __|  |  . `  | |  . `  | |  | |   __|  |   __|  |      /     
|  `--'  | |  |____ |  |\   | |  |\   | |  | |  |     |  |____ |  |\  \----.
 \______/  |_______||__| \__| |__| \__| |__| |__|     |_______|| _| `._____|
                                                                            
The most advanced password recovery 
For all version of .kdbx (KeePass 2.X) by: @byt3n33dl3
                                                                  version: 1.1.0
[+] KeePass database detected (version 4)
[+] Using AES-KDF key derivation
[+] Starting password cracking with 14344400 passwords
[+] Progress: 38/14344400 (0.00%) - 142 p/m - ETA: 70d 3h 36m 38s - Current: liverpool
[+] Password found: liverpool
```

## CONTACT

For more, come to my collections of write-ups for real-world use cases and write-ups [here](https://github.com/byt3n33dl3/thc-jennifer/blob/main/USAGE.md) if there's any security concern, please contact me at <byt3n33dl3@pm.me>