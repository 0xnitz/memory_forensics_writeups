# Sality

## Information Gathering

Well, you know the drill, pslist first.

```
python vol.py -f sality.vmem pslist
```

![image-20201001182651696](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001182651696.png)

Well, the machine's uptime is around four days, everything looks legit besides the aelas process, that I don't know.
With an eyebrow raised and my eyes on the name aelas.exe I also tried psxview and found nothing out of the ordinary.

## Injections

Enough beating around the bush, let's inspect malfind's output

```
python vol.py -f sality.vmem malfind
```

We have a few types of injections and I'll divide them into groups:

* Shellcode injections of this type
  ![image-20201001183029549](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001183029549.png)
* Strings of the process name and pid
  ![image-20201001183151953](C:\Users\Nitzan\AppData\Roaming\Typora\typora-user-images\image-20201001183151953.png)

* Empty shellcode that have code starting at offset 1000
* An MZ file injected into aelas

### aelas

This process stood out as the suspicious target for my investigation, let's look at that injected MZ file.

```
python vol.py -f sality.vmem vaddump...
```

Looking at the file in 010 I see the file is UPX packed (red flag), and after analyzing it's strings I'm pretty sure it's malicious

* explorer.exe (a process with injections similar to this)
* filemon
* A lot of url patterns
* A lot of reg paths that display system information
* C:\WINDOWS\system32\drivers\nhsmo.sys
* SeDebugPrivilege
* autorun.inf (probably to infect removable drives)
* system.ini
* PsLookupProcessByProcessId
* ZwClose
* Services strings
* VirtualProtect (probably for injection purposes)
* GetTokenInfo/AdjustTokenPrivs
* RegOpen/RegDelete/RegCreate/RegSetValue
* WriteProcessMemory/CreateRemoteThread (big, big red flags)
* CreateProcess
* Process32Next/Process32First/Module32Next/Module32First (for iterating over processes/modules probably)
* TROJAN
* System\CurrentControlSet\SafeBoot
* Symantec/McAfee/ESET/avast
* InternetOpen/Close
* DeleteService/ControlService/CreateService
* AntiVirusDisableNotify
* SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile
* And many, many more...

Checking the process' handles I see a few more interesting handles that keep on feeding my suspicions.

* aelas.exeM_1984_ mutex (that's the string found in the injection!)
* \Device\Afd\Endpoint (using the network)
* winlogon.exeM_632_/vmupgradehelper.exeM_1788_/tpautoconnsvc.exeM_1968_/wuauclt.exeM_1732_/smss.exeM_544_/... (These are the mutex names injected into other processes!)

