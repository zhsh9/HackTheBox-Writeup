# Devvortex

## Machine Info

![image-20231128232453970](./Devvortex.assets/image-20231128232453970.png)

## Recon

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- attack vector: 80 - http
- devvortex.htb - nothing
- subdomain enum

```
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.devvortex.htb Status: 200 [Size: 23221]
```

- http://dev.devvortex.htb

![image-20231128232614190](./Devvortex.assets/image-20231128232614190.png)

- Joomla

![image-20231128232633583](./Devvortex.assets/image-20231128232633583.png)

## Foothold

### 80 - joomla

![image-20231128232738739](./Devvortex.assets/image-20231128232738739.png)

- user: admin, joomla 4.2.6, db: mysql, postgresql
- searchsploit joomla exp

![image-20231128232920635](./Devvortex.assets/image-20231128232920635.png)

- [Joomla! v4.2.8 - Unauthenticated information disclosure - PHP webapps Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/51334)

![image-20231128233007917](./Devvortex.assets/image-20231128233007917.png)

- cred: **lewis:P4ntherg0t1n5r3c0n##** -> login ok

![image-20231128233039993](./Devvortex.assets/image-20231128233039993.png)

![image-20231128233044492](./Devvortex.assets/image-20231128233044492.png)

- users: **lewis**, **logan**
- **editor template php file** to get web shell

![image-20231128233106679](./Devvortex.assets/image-20231128233106679.png)

- poc:

![image-20231128233115371](./Devvortex.assets/image-20231128233115371.png)

- curl local reverse shell file to execute while listening 1234 port on local -> www-data **get shell**

![image-20231128233202334](./Devvortex.assets/image-20231128233202334.png)

## Privilege Escalation

### www-data -> logan

- enum

![image-20231128233249383](./Devvortex.assets/image-20231128233249383.png)

```bash
www-data@devvortex:/home/logan$ cat /etc/passwd | grep bash
cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
logan:x:1000:1000:,,,:/home/logan:/bin/bash
```

- `netstat -tunl` -> 3306 **mysql** serice enbale
- connect mysql using **lewis** cred in Joomla

![image-20231128233423327](./Devvortex.assets/image-20231128233423327.png)

![image-20231128233426499](./Devvortex.assets/image-20231128233426499.png)

- hash of logan password -> hashcat to crack

![image-20231128233452744](./Devvortex.assets/image-20231128233452744.png)

- cred: **logan:tequieromucho**

### logan -> root

- `sudo -l` -> attack vector

![image-20231128233515229](./Devvortex.assets/image-20231128233515229.png)

- searchsploit -> 49572 [x], 37088 [x]

![image-20231128233549339](./Devvortex.assets/image-20231128233549339.png)

![image-20231128233619360](./Devvortex.assets/image-20231128233619360.png)

- offical repo information gathering: [canonical/apport: Apport intercepts Program crashes, collects debugging information about the crash and the operating system environment, and sends it to bug trackers in a standardized form. It also offers the user to report a bug about a package, with again collecting as much information about it as possible. (github.com)](https://github.com/canonical/apport)
- seeking code changes from commits:

![image-20231128233714980](./Devvortex.assets/image-20231128233714980.png)

![image-20231128233837700](./Devvortex.assets/image-20231128233837700.png)

- [Bug #2016023 “viewing an apport-cli crash with default pager cou...” : Bugs : apport package : Ubuntu (launchpad.net)](https://bugs.launchpad.net/ubuntu/+source/apport/+bug/2016023)

![image-20231128233849093](./Devvortex.assets/image-20231128233849093.png)

- also checking this poc from git commit page (version 2.26.1)

![image-20231128233917247](./Devvortex.assets/image-20231128233917247.png)

- poc: [fix: Do not run sensible-pager as root if using sudo/pkexec · canonical/apport@e5f78cc (github.com)](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb)

![image-20231128233933119](./Devvortex.assets/image-20231128233933119.png)

- exp

![image-20231128233938291](./Devvortex.assets/image-20231128233938291.png)

![image-20231128233948748](./Devvortex.assets/image-20231128233948748.png)

![image-20231128233952258](./Devvortex.assets/image-20231128233952258.png)

**Hint**: open source program -> check repo and commits, versions, logs, news about this program -> get detailed info of it
