# Prolanco Writeup

## Finding the suspicious process

The challenge instructions stated we have a different, un-ordinary process. I tried executing pslist to see the system state and maybe spot something weird.

```
python vol.py -f prolaco.vmem pslist
```

![image-20201001094838639](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001094838639.png)

Looks like the machine booted at 6:06 and we have a debugger process started at about 16:50, nice.
Lets try psxview to see if we have some hidden/terminated processes

```
python vol.py -f prolaco.vmem psxview
```

![image-20201001095122324](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001095122324.png)

Easy! look at pid 1336 (1_doc_RCData_61), not attached to the PsActiveProcessHead list and still running, that's a hidden process in the wild.
We also have a msiexec/rundll processes terminated very close together, they might be linked to our possibly malicious process, lets check it's start time

![image-20201001095529764](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001095529764.png)

We can't ignore the fact we have a vmem, maybe someone tried to debug our malicious process.

## Extracting additional information

Let's see what sids our process has

```
python vol.py -f prolaco.vmem getsids --offset=0x0113f648
```

![image-20201001095900629](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001095900629.png)

Nice, admin
I'll try the privileges next

```
python vol.py -f prolaco.vmem privs --offset=0x0113f648
```

![image-20201001103250900](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001103250900.png)

Nice, debug privilege for accessing other processes, load driver and shutdown privileges to change important system values (MBR, drivers)

Maybe the environment variables can shed some more light on this process.

```
python vol.py -f prolaco.vmem envars --offset=0x0113f648
```

![image-20201001100128182](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001100128182.png)

Looks like we have a Windows NT system on our hands, the domain is named BILLY-DB5B9DD3 but nothing really interesting.
I'll try vadinfo to maybe find the exe path.

```
python vol.py -f prolaco.vmem vadinfo --offset=0x0113f648
```

![image-20201001100356206](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001100356206.png)

[snip]

The file is on the admin desktop, okay. We also see a vad node pointing to the windows sockets, hmm, the malware is probably communicating.

![image-20201001100816001](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001100816001.png)

Wow! looks like ImmunityDebugger started our malware.
Maybe the cmdline plugin will have some more useful data

![image-20201001101805884](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001101805884.png)

Nope, not really, we already know that.
Let's try and check the handles
![image-20201001101950302](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001101950302.png)

Okay, we know the malware has a shell semaphore and has a Windows Common Controls File Object. We also see our desktop file again, and, what? what is the mutex name? Maybe the malware tries to pass it's mutex as a google mutex.

## Static Analysis

We have a lot of information, let's try to fully asses our suspicions and dump the process executable and analyze it.

After dumping the process executable Windows Defender Immediately jumps and classifies it as malware
![image-20201001102604876](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001102604876.png) 

Let's see for ourselves
![image-20201001102652365](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001102652365.png)

Looks like the file contains another files zipped with pkzip.
Now we'll move on to the strings:

* A lot of socket style strings. The malware obviously communicates with some server (we also have some urls)
* PsInitialSystemProcess, EnumProcesses, Process32Next, Module32Next The process enumerates the system processes and unlinks itself from the list.
* NtMapViewOfSection, NtUnmapViewOfSection maybe try to hide it's pkzip
* ZwQuerySystemInformation, very malware like function
* AdjustTokenPrivileges, That's probably how the token has all those privileges
* Service functions, maybe tries to register itself as a service for persistency
* Yup, run registry keys, we have persistency
* GetLogicalDriveStrings, maybe tries to expand over connected removable/network drives 