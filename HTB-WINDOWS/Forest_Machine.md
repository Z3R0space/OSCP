# Machine Information

- **IP:** 10.10.10.161
- **OS:** Windows

---
# Recon - Information Gathering

Initial step of any hack is to do reconnaissance of a system or network to gather passive and active information linked with your target. The initial stage for this recon is scanning for open ports and services, so we can explore ways to exploit our way in the system.

**Commands:**
- `sudo nmap -sT -p- 10.10.10.161 -oG nmapForestTCP`
- `grep "Ports:" nmapForestTCP | sed -n 's/.*Ports: //p' | tr ', ' '\n' | grep "/open" | cut -d '/' -f1 | paste -sd,`
- `- sudo nmap -sVC -p [ports] 10.10.10.161 -oG nmapForestFullTCP`

![](images-forest/1.png)

Once we have a list of open ports, it is time to gather detail service information about the ports open, so we can look at service name, service version, and detailed service information which might be useful for further enumeration or exploitation.

![](images-forest/2.png)

**Output:**

```
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-05-17 02:51:06Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
49975/tcp open  msrpc        Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 2016|2019
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2019
OS details: Microsoft Windows Server 2016 or Server 2019
Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-05-16T19:51:57-07:00
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h26m48s, deviation: 4h02m30s, median: 6m47s
| smb2-time:
|   date: 2025-05-17T02:52:00
|_  start_date: 2025-05-17T02:34:54
```

Looking at the output, we can see too many services running on the machine and services like DNS (53) & Kerberos (88) defines that this is a Domain Controller (DC). Other major ports to focus on are NetBIOS (139), Ldap (389), and SMB (445).

## SMB Enumeration

SMB enumeration is a critical, often low-hanging-fruit, security reconnaissance process that gathers information from *Server Message Block (SMB)* services (port 139/445), including hostnames, shares, user accounts, and operating system details.

**Command:**
- `sudo nmap -p445 --script smb-enum-* forest.htb | tee nmapForestSMBenum`

![](images-forest/3.png)

**Output:**

```
PORT    STATE SERVICE
445/tcp open  microsoft-ds
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
Host script results:
| smb-enum-users:
|   HTB\$331000-VK4ADACQNUCA (RID: 1123)
|     Flags:       Normal user account, Password not required, Account disabled, Password Expired
|   HTB\Administrator (RID: 500)
|     Full name:   Administrator
|     Description: Built-in account for administering the computer/domain
|     Flags:       Normal user account
|   HTB\andy (RID: 1150)
|     Full name:   Andy Hislip
|     Flags:       Normal user account, Password does not expire
|   HTB\DefaultAccount (RID: 503)
|     Description: A user account managed by the system.
|     Flags:       Normal user account, Password not required, Account disabled, Password does not expire
|   HTB\Guest (RID: 501)
|     Description: Built-in account for guest access to the computer/domain
|     Flags:       Normal user account, Password not required, Account disabled, Password does not expire
|   HTB\HealthMailbox0659cc1 (RID: 1144)
|     Full name:   HealthMailbox-EXCH01-010
|     Flags:       Normal user account, Password does not expire
|   HTB\HealthMailbox670628e (RID: 1137)
|     Full name:   HealthMailbox-EXCH01-003
|     Flags:       Normal user account, Password does not expire
|   HTB\HealthMailbox6ded678 (RID: 1139)
|     Full name:   HealthMailbox-EXCH01-005
|     Flags:       Normal user account, Password does not expire
|   HTB\HealthMailbox7108a4e (RID: 1143)
|     Full name:   HealthMailbox-EXCH01-009
|     Flags:       Normal user account, Password does not expire
|   HTB\HealthMailbox83d6781 (RID: 1140)
|     Full name:   HealthMailbox-EXCH01-006
|     Flags:       Normal user account, Password does not expire
|   HTB\HealthMailbox968e74d (RID: 1138)
|     Full name:   HealthMailbox-EXCH01-004
|     Flags:       Normal user account, Password does not expire
|   HTB\HealthMailboxb01ac64 (RID: 1142)
|     Full name:   HealthMailbox-EXCH01-008
|     Flags:       Normal user account, Password does not expire
|   HTB\HealthMailboxc0a90c9 (RID: 1136)
|     Full name:   HealthMailbox-EXCH01-002
|     Flags:       Normal user account, Password does not expire
|   HTB\HealthMailboxc3d7722 (RID: 1134)
|     Full name:   HealthMailbox-EXCH01-Mailbox-Database-1118319013
|     Flags:       Normal user account, Password does not expire
|   HTB\HealthMailboxfc9daad (RID: 1135)
|     Full name:   HealthMailbox-EXCH01-001
|     Flags:       Normal user account, Password does not expire
|   HTB\HealthMailboxfd87238 (RID: 1141)
|     Full name:   HealthMailbox-EXCH01-007
|     Flags:       Normal user account, Password does not expire
|   HTB\krbtgt (RID: 502)
|     Description: Key Distribution Center Service Account
|     Flags:       Normal user account, Account disabled
|   HTB\lucinda (RID: 1146)
|     Full name:   Lucinda Berger
|     Flags:       Normal user account, Password does not expire
|   HTB\mark (RID: 1151)
|     Full name:   Mark Brandt
|     Flags:       Normal user account, Password does not expire
|   HTB\santi (RID: 1152)
|     Full name:   Santi Rodriguez
|_    Flags:       Normal user account, Password does not expire
| smb-enum-domains:
|   HTB
|     Groups: Cert Publishers, RAS and IAS Servers, Allowed RODC Password Replication Group, Denied RODC Password Replication Group, DnsAdmins
|     Users: Administrator, Guest, krbtgt, DefaultAccount, $331000-VK4ADACQNUCA, SM_2c8eef0a09b545acb, SM_ca8c2ed5bdab4dc9b, SM_75a538d3025e4db9a, SM_681f53d4942840e18, SM_1b41c9286325456bb, SM_9b69f1b9d2cc45549, SM_7c96b981967141ebb, SM_c75ee099d0a64c91b, SM_1ffab36a2f5f479cb, HealthMailboxc3d7722, HealthMailboxfc9daad
|     Creation time: 2025-05-17T02:34:44
|     Passwords: min length: 7; min age: 1.0 days; max age: n/a days; history: 24 passwords
|     Account lockout disabled
|   Builtin
|     Groups: Account Operators, Pre-Windows 2000 Compatible Access, Incoming Forest Trust Builders, Windows Authorization Access Group, Terminal Server License Servers, Administrators, Users, Guests, Print Operators, Backup Operators, Replicator, Remote Desktop Users, Network Configuration Operators, Performance Monitor Users, Performance Log Users, Distributed COM Users, IIS_IUSRS, Cryptographic Operators, Event Log Readers, Certificate Service DCOM Access, RDS Remote Access Servers, RDS Endpoint Servers, RDS Management Servers, Hyper-V Administrators, Access Control Assistance Operators, Remote Management Users, System Managed Accounts Group, Storage Replica Administrators, Server Operators
|     Users: n/a
|     Creation time: 2016-07-16T13:19:09
|     Passwords: min length: n/a; min age: n/a days; max age: 42 days; history: n/a passwords
|_    Account lockout disabled
| smb-enum-shares:
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   [\\10.10.10.161\ADMIN$](file://10.10.10.161/ADMIN$):
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   [\\10.10.10.161\C$](file://10.10.10.161/C$):
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   [\\10.10.10.161\IPC$](file://10.10.10.161/IPC$):
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: READ
|   [\\10.10.10.161\NETLOGON](file://10.10.10.161/NETLOGON):
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: <none>
```

We get tons of information back from `smb-enum` NSE script, but `smb-vuln` fails. We cannot access any of the available shares through anonymous/guest user. Major information we get is available users, domain information, local & domain groups, and basic share information. Next, step I like to do is to enumerate LDAP before diving deep into SMB.