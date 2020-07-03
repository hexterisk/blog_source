---
author:
  name: "hexterisk"
date: 2020-03-13
linktitle: Trace Analysis
type:
- post
- posts
title: Trace Analysis
tags: ["binary", "rev", "reversing", "c", "pe", "windows"]
weight: 10
categories: ["basic-binary-analysis"]
---

## System Call Trace

**strace** can be used to investigate system call behavior. In some cases, you may want to attach strace to a running process. To do this, you need to use the -p pid option, where pid is the process ID of the process you want to attach to.

```C
$ strace ./ctf show_me_the_flag
➊ execve("./ctf", ["./ctf", "show_me_the_flag"], [/* 73 vars */]) = 0
brk(NULL) = 0x1053000
access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f703477e000
access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
➋ open("/ch3/tls/x86_64/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or ...)
stat("/ch3/tls/x86_64", 0x7ffcc6987ab0) = -1 ENOENT (No such file or directory)
open("/ch3/tls/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat("/ch3/tls", 0x7ffcc6987ab0) = -1 ENOENT (No such file or directory)
open("/ch3/x86_64/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat("/ch3/x86_64", 0x7ffcc6987ab0) = -1 ENOENT (No such file or directory)
open("/ch3/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = 3
➌ read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0p\t\0\0\0\0\0\0"..., 832) = 832
fstat(3, st_mode=S_IFREG|0775, st_size=10296, ...) = 0
mmap(NULL, 2105440, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f7034358000
mprotect(0x7f7034359000, 2097152, PROT_NONE) = 0
mmap(0x7f7034559000, 8192, PROT_READ|PROT_WRITE, ..., 3, 0x1000) = 0x7f7034559000
close(3) = 0
open("/ch3/libstdc++.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, st_mode=S_IFREG|0644, st_size=150611, ...) = 0
mmap(NULL, 150611, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f7034759000
close(3) = 0
access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory)
➍ open("/usr/lib/x86_64-linux-gnu/libstdc++.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0 \235\10\0\0\0\0\0"..., 832) = 832
fstat(3, st_mode=S_IFREG|0644, st_size=1566440, ...) = 0
mmap(NULL, 3675136, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f7033fd6000
mprotect(0x7f7034148000, 2097152, PROT_NONE) = 0
mmap(0x7f7034348000, 49152, PROT_READ|PROT_WRITE, ..., 3, 0x172000) = 0x7f7034348000
mmap(0x7f7034354000, 13312, PROT_READ|PROT_WRITE, ..., -1, 0) = 0x7f7034354000
close(3) = 0
open("/ch3/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory)
open("/lib/x86_64-linux-gnu/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0p*\0\0\0\0\0\0"..., 832) = 832
fstat(3, st_mode=S_IFREG|0644, st_size=89696, ...) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f7034758000
mmap(NULL, 2185488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f7033dc0000
mprotect(0x7f7033dd6000, 2093056, PROT_NONE) = 0
mmap(0x7f7033fd5000, 4096, PROT_READ|PROT_WRITE, ..., 3, 0x15000) = 0x7f7033fd5000
close(3) = 0
open("/ch3/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory)
open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0"..., 832) = 832
fstat(3, st_mode=S_IFREG|0755, st_size=1864888, ...) = 0
mmap(NULL, 3967392, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f70339f7000
mprotect(0x7f7033bb6000, 2097152, PROT_NONE) = 0
mmap(0x7f7033db6000, 24576, PROT_READ|PROT_WRITE, ..., 3, 0x1bf000) = 0x7f7033db6000
mmap(0x7f7033dbc000, 14752, PROT_READ|PROT_WRITE, ..., -1, 0) = 0x7f7033dbc000
close(3) = 0
open("/ch3/libm.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT (No such file or directory)
open("/lib/x86_64-linux-gnu/libm.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0V\0\0\0\0\0\0"..., 832) = 832
fstat(3, st_mode=S_IFREG|0644, st_size=1088952, ...) = 0
mmap(NULL, 3178744, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f70336ee000
mprotect(0x7f70337f6000, 2093056, PROT_NONE) = 0
mmap(0x7f70339f5000, 8192, PROT_READ|PROT_WRITE, ..., 3, 0x107000) = 0x7f70339f5000
close(3) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f7034757000
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f7034756000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f7034754000
arch_prctl(ARCH_SET_FS, 0x7f7034754740) = 0
mprotect(0x7f7033db6000, 16384, PROT_READ) = 0
mprotect(0x7f70339f5000, 4096, PROT_READ) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f7034753000
mprotect(0x7f7034348000, 40960, PROT_READ) = 0
mprotect(0x7f7034559000, 4096, PROT_READ) = 0
mprotect(0x601000, 4096, PROT_READ) = 0
mprotect(0x7f7034780000, 4096, PROT_READ) = 0
munmap(0x7f7034759000, 150611) = 0
brk(NULL) = 0x1053000
brk(0x1085000) = 0x1085000
fstat(1, st_mode=S_IFCHR|0620, st_rdev=makedev(136, 1), ...) = 0
➎ write(1, "checking 'show_me_the_flag'\n", 28checking 'show_me_the_flag'
) = 28
➏ write(1, "ok\n", 3ok
) = 3
➐ exit_group(1) = ?
+++ exited with 1 +++
```

When tracing a program from the start, strace includes all the system calls used by the program interpreter to set up the process, making the output quite verbose. The first system call in the output is execve, which is called by your shell to launch the program ➊. After that, the program interpreter takes over and starts setting up the execution environment. This involves setting up memory regions and setting the correct memory access permissions using mprotect. Additionally, you can see the system calls used to look up and load the required dynamic libraries. The dynamic linker is searching for the lib5ae9b7f.so library in a number of standard subfolders, followed by in your current working directory (➋ /ch3) since LD\_LIBRARY\_PATH environment variable was set to it earlier to tell the dynamic linker to add your current working directory to its search path. When the library is found, the dynamic linker reads it and maps it into memory ➌. The setup process is repeated for other required libraries, such as libstdc++.so.6 ➍, and it accounts for the vast majority of the strace output. It isn’t until the last three system calls that you finally see application specific behavior. The first system call used is write, which is used to print checking 'show\_me\_the\_flag' to the screen ➎. You see another write call to print the string ok ➏, and finally, there’s a call to exit\_group, which leads to the exit with status code 1 ➐.

## Library Call Trace

**ltrace** can be used to investigate system call behavior.

```C
$ ltrace -i -C ./ctf show_me_the_flag
➊ [0x400fe9] __libc_start_main (0x400bc0, 2, 0x7ffc22f441e8, 0x4010c0 <unfinished ...>
➋ [0x400c44] __printf_chk (1, 0x401158, 0x7ffc22f4447f, 160checking 'show_me_the_flag') = 28
➌ [0x400c51] strcmp ("show_me_the_flag", "show_me_the_flag") = 0
➍ [0x400cf0] puts ("ok"ok) = 3
➎ [0x400d07] rc4_init (rc4_state_t*, unsigned char*, int)
(0x7ffc22f43fb0, 0x4011c0, 66, 0x7fe979b0d6e0) = 0
➏ [0x400d14] std::__cxx11::basic_string<char, std::char_traits<char>,
std::allocator<char> >:: assign (char const*)
(0x7ffc22f43ef0, 0x40117b, 58, 3) = 0x7ffc22f43ef0
➐ [0x400d29] rc4_decrypt (rc4_state_t*, std::__cxx11::basic_string<char,
std::char_traits<char>, std::allocator<char> >&)
(0x7ffc22f43f50, 0x7ffc22f43fb0, 0x7ffc22f43ef0, 0x7e889f91) = 0x7ffc22f43f50
➑ [0x400d36] std::__cxx11::basic_string<char, std::char_traits<char>,
std::allocator<char> >:: _M_assign (std::__cxx11::basic_string<char,
std::char_traits<char>, std::allocator<char> > const&)
(0x7ffc22f43ef0, 0x7ffc22f43f50, 0x7ffc22f43f60, 0) = 0
➒ [0x400d53] getenv ("GUESSME") = nil
[0xffffffffffffffff] +++ exited (status 1) +++
```

The first library call is \_\_libc\_start\_main ➊, which is called from the \_start function to transfer control to the program’s main function. Once main is started, its first library call prints the now familiar checking ... string to the screen ➋. The actual check turns out to be a string comparison, which is implemented using strcmp, and verifies that the argument given to ctf is equal to show\_me\_the\_flag ➌. If this is the case, ok is printed to the screen ➍. So far, this is mostly behavior you’ve seen before. But now you see something new: the RC4 cryptography is initialized through a call to rc4\_init, which is located in the library you extracted earlier ➎. After that, you see an assign to a C++ string, presumably initializing it with an encrypted message ➏. This message is then decrypted with a call to rc4\_decrypt ➐, and the decrypted message is assigned to a new C++ string ➑. Finally, there’s a call to getenv, which is a standard library function used to look up environment variables ➒. You can see that ctf expects an environment variable called GUESSME! The name of this variable may well be the string that was decrypted earlier. Let’s see whether ctf ’s behavior changes when you set a dummy value for the GUESSME environment variable as follows:

```C
$ GUESSME='foobar' ltrace -i -C ./ctf show_me_the_flag
...
[0x400d53] getenv ("GUESSME") = "foobar"
➊ [0x400d6e] std::__cxx11::basic_string<char, std::char_traits<char>,
std::allocator<char> >:: assign (char const*)
(0x7fffc7af2b00, 0x401183, 5, 3) = 0x7fffc7af2b00
➋ [0x400d88] rc4_decrypt (rc4_state_t*, std::__cxx11::basic_string<char,
std::char_traits<char>, std::allocator<char> >&)
(0x7fffc7af2b60, 0x7fffc7af2ba0, 0x7fffc7af2b00, 0x401183) = 0x7fffc7af2b60
[0x400d9a] std::__cxx11::basic_string<char, std::char_traits<char>,
std::allocator<char> >:: _M_assign (std::__cxx11::basic_string<char,
std::char_traits<char>, std::allocator<char> > const&)
(0x7fffc7af2b00, 0x7fffc7af2b60, 0x7700a0, 0) = 0
[0x400db4] operator delete (void*)(0x7700a0, 0x7700a0, 21, 0) = 0
➌ [0x400dd7] puts ("guess again!"guess again!) = 13
[0x400c8d] operator delete (void*)(0x770050, 0x76fc20, 0x7f70f99b3780, 0x7f70f96e46e0) = 0
[0xffffffffffffffff] +++ exited (status 1) +++
```

After the call to getenv, ctf goes on to assign ➊ and decrypt ➋ another C++ string. Unfortunately, between the decryption and the moment that guess again is printed to the screen ➌, you don’t see any hints regarding the expected value of GUESSME. This tells you that the comparison of GUESSME to its expected value is implemented without the use of any library functions.
