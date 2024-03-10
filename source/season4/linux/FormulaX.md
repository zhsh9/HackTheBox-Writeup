# FormulaX

## Machine Info

![image-20240311031918406](https://raw.githubusercontent.com/zhsh9/htb-season4-imgs/main/FormulaX.assets/image-20240311031918406.png)

<p align="center"><strong>Notice: the full version of write-up is <a href="https://zhsh9.info/HackTheBox/2024/season4/linux/FormulaX/" style="color: red;">here</a>.</strong></p>

## Beyond Root

### Basic XSS Prevention

```javascript
function htmlEncode(str) {
  return String(str).replace(/[^\w. ]/gi, function (c) {
    return '&#' + c.charCodeAt(0) + ';';
  });
}
```

The `htmlEncode` function prevents XSS attacks by converting special characters in a string to their corresponding HTML entity codes. In HTML, certain characters are special, such as `<` and `>` which are used to denote the beginning and end of tags, respectively. If user input contains these special characters and is inserted directly into HTML, an attacker could potentially inject malicious script code. By converting these characters into their corresponding character entities (for example, converting `<` to `&lt;`), it prevents the browser from misinterpreting user input as code to be executed.
