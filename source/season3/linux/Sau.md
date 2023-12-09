# Sau

## Machine Info

![image-20231201084248046](./Sau.assets/image-20231201084248046.png)

## Recon

![image-20231201160321848](./Sau.assets/image-20231201160321848.png)

![image-20231201160324706](./Sau.assets/image-20231201160324706.png)

![image-20231201160331245](./Sau.assets/image-20231201160331245.png)

- open source repo: https://github.com/darklynx/request-baskets, Version: **1.2.1**

## Foothold

### explore 2 vulnerable services

![image-20231201160408907](./Sau.assets/image-20231201160408907.png)

- POC: SSRF Vuln [y]

![image-20231201160413640](./Sau.assets/image-20231201160413640.png)

- new a brasket -> forward this site to another site 127.0.0.1:**80** (filtered port)

![image-20231201160522797](./Sau.assets/image-20231201160522797.png)

![image-20231201160530093](./Sau.assets/image-20231201160530093.png)

- 80 port's service: **Maltail 0.53**; 

- **vuln**: the `username` parameter of the login page doesn't properly sanitize the input, allowing an attacker to inject OS commands

- [spookier/Maltrail-v0.53-Exploit: RCE Exploit For Maltrail-v0.53 (github.com)](https://github.com/spookier/Maltrail-v0.53-Exploit/tree/main)

![image-20231201160604804](./Sau.assets/image-20231201160604804.png)

### combine them together to get user shell

- [zhsh9/Request-Baskets-v1.2.1-Trigger-Maltrail-v0.53-Exploit: HTB Sau POC: RCE exploit for Maltrail v0.53 triggered by Request Baskets v1.2.1 (github.com)](https://github.com/zhsh9/Request-Baskets-v1.2.1-Trigger-Maltrail-v0.53-Exploit)

![image-20231201160728796](./Sau.assets/image-20231201160728796.png)

## Privilege Escalation

- `sudo -l` -> systemctrl sudo -> less-like -> !sh

![image-20231201160801031](./Sau.assets/image-20231201160801031.png)

![image-20231201160804011](./Sau.assets/image-20231201160804011.png)

## Exploit Chain

SSRF -> forward 80 serice -> RCE -> get user shell -> sudo systemctl -> get root shell
