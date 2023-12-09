# Bashed

## Machine Info

![image-20231201052647155](./Bashed.assets/image-20231201052647155.png)

## Recon

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (96%), Linux 3.13 (96%), Linux 3.2 - 4.9 (96%), Linux 3.8 - 3.11 (96%), Linux 4.8 (96%), Linux 4.4 (95%), Linux 4.9 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 4.2 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```

- path enum -> attack vector dir: dev, php, uploads

```
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum:
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /php/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|_  /uploads/: Potentially interesting folder
```

## Foothold

- hint: phpbash

![image-20231201051240533](./Bashed.assets/image-20231201051240533.png)

- check dirs -> dev/phpbash.php

![image-20231201051259715](./Bashed.assets/image-20231201051259715.png)

![image-20231201051311896](./Bashed.assets/image-20231201051311896.png)

- find writable directory -> **uploads**

![image-20231201051337964](./Bashed.assets/image-20231201051337964.png)

- upload shell.php -> get www-data user shell

![image-20231201051408301](./Bashed.assets/image-20231201051408301.png)

## Privilege Escalation

- /scripts unseen as www-data

![image-20231201051419303](./Bashed.assets/image-20231201051419303.png)

### www-data -> scriptmanager

![image-20231201051448668](./Bashed.assets/image-20231201051448668.png)

### scriptmanager -> root

![image-20231201051452453](./Bashed.assets/image-20231201051452453.png)

So, must be root who run `python test.py`. Change test.py and **watch test.txt**.

![image-20231201051537416](./Bashed.assets/image-20231201051537416.png)

Therefore, root run this py as a **scheduled task**.

Write reverse shell into test.py -> get root shell

![image-20231201052416005](./Bashed.assets/image-20231201052416005.png)

## Exploit Chain

semi web shell -> upload rshell.php -> get user priv -> enum a scheduled python file -> change it to py rshell file -> listen on local to get root priv
