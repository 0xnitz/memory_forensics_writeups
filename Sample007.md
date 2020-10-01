# Sample007

Before we dive right in, the name "Sample007.bin" sounds like a sample of malware, keep that in mind.

## General Information Gathering

I like starting with pslist to get an understanding of the system state when the memory "image" was taken.

```
python vol.py -f sample007.bin pslist
```

![image-20201001145522256](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001145522256.png)

First of, this machine is up for at least 7 months, might be a server of some sort.

What is this?! 3 lsass processes?!
This absolutely screams process hollowing. Also, looks like only one lsass is started from winlogon, the other 2 from services.
I'll take a wild guess and say that pids 868/1928 are our malicious processes.

I tried psxview to see if we have any hidden processes, we don't.

![image-20201001150100804](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001150100804.png)

These are all the processes that have start times similar to both the (probably) malicious lsass processes.
Looks like someone opened procmon from explorer and looked at the processes, wmi was also running, and ipconfig was executed from the command line.

## Code Injection Overview

### Lsass Processes/Services/Svchost

Well, the exercise states we have code injection, using our newly gathered knowledge about both lsass processes, let's investigate

```
python vol.py -f sample007.bin malfind
```

We get a lot of output, a lot of the injection are MZ files, this might be a dll injection.
I started out by dumping one of the lsass' modules

```
python vol.py -f sample007.bin dlldump --dumpdir=. -p 1928
```

We get a lot of modules but only one looks kind of weird
![image-20201001154909302](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001154909302.png)

Windows defender jumps again, saying it's malware.
I investigated and so the file has a UPX section, too many suspicious strings to count, a full executable in the resources, also Virustotal classifies it as stuxnet/duqu. I think this is enough to say we have an infected process, the story is the same for lsass 868.

I think the malware probably used CreateProcess and hollowed out two lsass processes.

We also see the strings kernel32.dll and ZwMapViewOfSection injected into the processes, this is probably an indication that GetProcAddress was called.

### csrss

![image-20201001162424418](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001162424418.png)

This doesn't raise any alarm, let's check offset 1000 to maybe find some logic just like the example in the book

```
python vol.py -f sample007.bin volshell -p 600
dis(0x7f6f1000)
```

This doesn't yield any results, I'm classifying this injection as innocent.

### explorer

![image-20201001162724448](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001162724448.png)

These bytes aren't code, also checking offset 1000 doesn't yield anything, innocent!

## Hooks

### Lsass/Svchost/Services

They all have the same hook on the following list of functions

* ZwQuerySection

* ZwQueryAttributesFile

* ZwOpenFile

* ZwMapViewOfSection

* ZwCreateSection

* ZwClose

* NtQuerySection

* NtQueryAttributesFile

* NtOpenFile

* NtMapViewOfSection

* NtCreateSection

* NtClose

These are all syscall hooks on ntdll functions, they have the following template

```assembly
mov eax, num ; Sometimes missing
mov edx, func_addr
call edx
nop
mov eax, num + 1
```

After a little investigating and reading documentation I realized these hooks are changing the handles passed on to the functions! The hooks that are missing the first line don't have a handle parameter.
So, these hooks change the handles passed on to these functions.

I tried searching for these handle ids in the handle tables of all processes with some success.

### vmtoolsd

![image-20201001174204716](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001174204716.png)

After some searching with volshell this hook appears to do a lot, and even some weird stuff.
I decided to search the web and found that glib-2.0.dll is a vmware signed dll that is hooking a vmware process, this is an innocent hook!

### explorer/tsvncache

![image-20201001174323350](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001174323350.png)

I never seen before the process tsvncache.exe or the module libapr_tsvn.dll so I decided to google search them.
I found out that tsvncache is a process part of TortoiseSVN and it keeps track of clipboard data. A clipboard tracking service having hooks in explorer.exe actually makes some sense, so this hook is innocent