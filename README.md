<h1 align="center">
  <a href=https://github.com/byt3n33dl3/thc-jennifer><img src="/src/img/README-logo.png" alt="thc-Jennifer" width="280px">
  <br>
</h1>

<p align="center">
  <a href="https://github.com/byt3n33dl3/thc-jennifer/blob/main/USAGE.md">Wiki</a> •
  <a href="https://github.com/byt3n33dl3/thc-jennifer/blob/main/INSTALL.md">Install</a>
</p>

<div align="center">
<h1>thc-Jennifer</h1>
The most advanced password recovery for all version of .kdbx (KeePass 2.X) 
<p></div>

![C Language](https://img.shields.io/badge/language-C-blue.svg)

```
  (c) 2025 by byt3n33dl3 <https://github.com/byt3n33dl3>
      Advanced KeePass Password Cracker, 1.1.0
              Licensed under BSD-2.0
```

Jennifer du' Casse is the most Advanced KeePass .kdbx cracking software. Support cracking KDBX3 (KeePass 2.x) and KDBX4. Designed to handle all versions of KeePass database files (.kdbx), including the newer 2.36+ versions that use the KDBX4 format.

Please do not use in military or secret service organizations, or for illegal purposes. (This is the wish of the author and non-binding. Many people working in these organizations do not care for laws and ethics anyways. You are not one of the "good" ones if you ignore this.)

Unlike some existing tools, Jennifer can efficiently process both AES-KDF and Argon2-based key derivation methods.

- Supports all KeePass versions (including >=2.36)
- Works with both _AES-KDF_ and Argon2 key derivation
- Multi-threaded for maximum performance
- Includes default wordlist for quick testing
- Progress tracking with accurate ETA
- Simple command-line interface

_Jennifer Operates by directly parsing the KDBX file structure to extract cryptographic parameters such as:_

- Master seed
- Transform seed (KDBX3)
- Encryption IV
- Stream start bytes
- KDF parameters (including Argon2 parameters for KDBX4)

_The binary implements several key technologies:_

- Multi-threaded password attempts for maximum performance
- Direct KDBX format parsing (both v3 and v4)
- Real-time progress statistics with ETA calculation
- Automatic detection of KeePass database version and encryption method
- Memory-efficient wordlist processing

# FUNCTIONS

- Parses the KDBX header to determine version and encryption parameters
- Loads the wordlist into memory for efficient processing
- Spawns multiple worker threads to attempt passwords in parallel
- Uses cryptographic operations to verify each password against the database
- Provides real-time statistics on cracking progress
- Immediately reports when a password is successfully found

## ISSUE

- ASCII Banner Sys
- CPU Usage

## Pull-Request

Your pull request should fully describe the functionality you are adding/removing or the problem you are solving. Regardless of whether your patch modifies one line or one thousand lines, you must describe what has prompted and/or motivated the change.

Solve only one problem in each pull request. If you're fixing a bug and adding a new feature, you need to make two separate pull requests. If you're fixing three bugs, you need to make three separate pull requests. 

If you're adding four new features, you need to make four separate pull requests.

## CONTACT

For more, come to my collections of write-ups for real-world use cases and write-ups [here](https://github.com/byt3n33dl3/thc-jennifer/blob/main/USAGE.md) if there's any security concern, please contact me at <byt3n33dl3@pm.me>