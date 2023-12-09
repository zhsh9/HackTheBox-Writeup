# CozyHosting

## Machine Info

![image-20231201123527736](./CozyHosting.assets/image-20231201123527736.png)

## Recon

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- path enum: dir + file

![image-20231201161002049](./CozyHosting.assets/image-20231201161002049.png)

![image-20231201161005444](./CozyHosting.assets/image-20231201161005444.png)

- dir **actuator** -> find sessions

![image-20231201161031653](./CozyHosting.assets/image-20231201161031653.png)

- enum authorized session `kanderson`

![image-20231201161117037](./CozyHosting.assets/image-20231201161117037.png)

## Foothold

- change site's cookies and login admin page

![image-20231201161149155](./CozyHosting.assets/image-20231201161149155.png)

- find ssh connection function

![image-20231201161229277](./CozyHosting.assets/image-20231201161229277.png)

- burp to capture the script's detail

![image-20231201161252030](./CozyHosting.assets/image-20231201161252030.png)

![image-20231201161256805](./CozyHosting.assets/image-20231201161256805.png)

- test the remote by connecting the local

![image-20231201161320350](./CozyHosting.assets/image-20231201161320350.png)

- curl a shell bash to execute on the remote -> rshell on the local

![image-20231201161349289](./CozyHosting.assets/image-20231201161349289.png)

## Privilege Escalation

### app -> josh

- `netstat -tuln`
- ps aux

```
app         1065 12.2 16.3 3672668 655944 ?      Ssl  02:11  10:24 /usr/bin/java -jar cloudhosting-0.0.1.jar
 
ps aux | grep sql
postgres    1111  0.0  0.7 218316 30248 ?        Ss   02:11   0:00 /usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main -c config_file=/etc/postgresql/14/main/postgresql.conf
```

![image-20231201161552287](./CozyHosting.assets/image-20231201161552287.png)

- shows that `cloudhosting-0.0.1.jar` and `postgresql` are running in the back

- analyse `cloudhosting-0.0.1.jar`

![image-20231201161532957](./CozyHosting.assets/image-20231201161532957.png)

![image-20231201161536996](./CozyHosting.assets/image-20231201161536996.png)

![image-20231201161557200](./CozyHosting.assets/image-20231201161557200.png)

- cred get: `"postgresql://postgres:Vg&nvzAQ7XxR@localhost:5432/"`

```bash
psql "postgresql://postgres:Vg&nvzAQ7XxR@localhost:5432/"
psql -h localhost -d postgres -U postgres
```

- conn to db -> enum -> get password's hash

![image-20231201161640983](./CozyHosting.assets/image-20231201161640983.png)

![image-20231201161700979](./CozyHosting.assets/image-20231201161700979.png)

![image-20231201161703571](./CozyHosting.assets/image-20231201161703571.png)

- hashcat to crack it

![image-20231201161718599](./CozyHosting.assets/image-20231201161718599.png)

- app priv -> josh priv

![image-20231201161743439](./CozyHosting.assets/image-20231201161743439.png)

### josh -> root

- sudo -l -> ssh -> `sudo /usr/bin/ssh -o ProxyCommand=';/usr/bin/bash 0<&2 1>&2' x`

![image-20231201161826158](./CozyHosting.assets/image-20231201161826158.png)

## Exploit Chain

session leakage -> web page login -> ssh function -> remote code execution -> get app-priv shell -> enum jar file and db service -> find db cred in jar file by re -> find hash in jar file -> crack hash -> get josh-priv shell -> sudo ssh -> get root shell
