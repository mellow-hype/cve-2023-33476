# CVE-2023-33476

> ReadyMedia (MiniDLNA) versions from 1.1.15 up to 1.3.2 is vulnerable to Buffer Overflow. The vulnerability is caused by incorrect validation logic when handling HTTP requests using chunked transport encoding. This results in other code later using attacker-controlled chunk values that exceed the length of the allocated buffer, resulting in out-of-bounds read/write.

- [Root Cause Analysis](https://blog.coffinsec.com/0day/2023/05/31/minidlna-heap-overflow-rca.html)
- [Exploit Details](https://blog.coffinsec.com/0day/2023/06/19/minidlna-cve-2023-33476-exploits.html)
- [NIST CVE Entry](https://nvd.nist.gov/vuln/detail/CVE-2023-33476)

## exploits

- RCE via tcache poisoning+GOT overwrite exploit for x86-64 target
- RCE via tcache poisoning+RIP overwrite exploit for arm32 target (Netgear RAX30)

## fuzzing

- source code dir tweaked for fuzzing
- libfuzzer harnesses used to find the bug

## src
vulnerable source code that can be built to reproduce/test exploits
