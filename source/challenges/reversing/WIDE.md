# WIDE

## Desc

We've received reports that Draeger has stashed a huge arsenal in the pocket dimension Flaggle Alpha. You've managed to smuggle a discarded access terminal to the Widely Inflated Dimension Editor from his headquarters, but the entry for the dimension has been encrypted. Can you make it inside and take control?

## Work

### Static Analysis

```console
$ file wide
wide: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=13869bb7ce2c22f474b95ba21c9d7e9ff74ecc3f, not stripped

$ ldd wide
        linux-vdso.so.1 (0x00007ffecfd28000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f61e1e000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f7f62234000)
```

![image-20240320174942371](./WIDE.assets/image-20240320174942371.png)

![image-20240320175012429](./WIDE.assets/image-20240320175012429.png)

![image-20240320175018173](./WIDE.assets/image-20240320175018173.png)

Password: sup3rs3cr3tw1d3

### Dynamic Analysis

```console
$ ./wide db.ex
[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
[*]                       Displaying Dimensions....                      [*]
[*]       Name       |              Code                |   Encrypted    [*]
[X] Primus           | people breathe variety practice  |                [*]
[X] Cheagaz          | scene control river importance   |                [*]
[X] Byenoovia        | fighting cast it parallel        |                [*]
[X] Cloteprea        | facing motor unusual heavy       |                [*]
[X] Maraqa           | stomach motion sale valuable     |                [*]
[X] Aidor            | feathers stream sides gate       |                [*]
[X] Flaggle Alpha    | admin secret power hidden        |       *        [*]
Which dimension would you like to examine? 1
The Ice Dimension
Which dimension would you like to examine? 2
The Berserk Dimension
Which dimension would you like to examine? 3
The Hungry Dimension
Which dimension would you like to examine? 4
The Water Dimension
Which dimension would you like to examine? 5
The Bone Dimension
Which dimension would you like to examine? 6
[X] That entry is encrypted - please enter your WIDE decryption key: imqwe
[X]                          Key was incorrect                           [X]
```

Flag:

```console
$ ./wide db.ex
[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
[*]                       Displaying Dimensions....                      [*]
[*]       Name       |              Code                |   Encrypted    [*]
[X] Primus           | people breathe variety practice  |                [*]
[X] Cheagaz          | scene control river importance   |                [*]
[X] Byenoovia        | fighting cast it parallel        |                [*]
[X] Cloteprea        | facing motor unusual heavy       |                [*]
[X] Maraqa           | stomach motion sale valuable     |                [*]
[X] Aidor            | feathers stream sides gate       |                [*]
[X] Flaggle Alpha    | admin secret power hidden        |       *        [*]
Which dimension would you like to examine? 6
[X] That entry is encrypted - please enter your WIDE decryption key: sup3rs3cr3tw1d3
HTB{som3_str1ng5_4r3_w1d3}
```
