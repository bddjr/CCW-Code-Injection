// ccw oauth 创建新会话并返回 token
// ctrl+shift+i 打开 devtools ，在控制台粘贴然后 enter

/** @license https://bddjr.github.io/tinyhmacmd5/lic */
{let r=1732584193,e=271733878,t=~r,n=~e,o=[],f=(f,a,h=0,i,l,u,d,c,g=[r,n,t,e],s=[...g],y=r=>g[3&++c])=>{for(f[a+64>>>9<<4|14]=0|a,f[a>>>5]|=128<<a%32;h<f.length;h+=16){for(c=i=0;i<64;c-=6)g[3&c]=0|((l=0|(l=y(),u=y(),d=y(),((a=i>>4<<2)?a>4?a>8?u^(l|~d):l^u^d:l&d|u&~d:l&u|~l&d)+(0|f[h+(i*(29521>>a)+(1296>>a)&15)])+(u="',16%).4$+07&*/5".charCodeAt(a+i%4)-32,o[63-i++]??=0|2**32*Math.abs(Math.sin(i)))+y()))<<u|l>>>32-u)+y();for(c=4;c;)s[--c]=g[c]=0|s[c]+g[c]}return g},a=(r,e,t=("string"==typeof r?r=(new TextEncoder).encode(r):r).length,n=[],o=8*t)=>{for(;t;)n[e+(--t>>>2)]|=r[t]<<t%4*8;return[n,o]};var md5=(r,e,t)=>{var n=16,o=null!=e,[h,i]=a(r,o*n),l=new Uint8Array(n);if(o){let[r,t]=a(e,0),o=e=>{for(;n;)h[--n]=16843009*e^r[n];n=16};t>512&&(r=f(r,t)),o(54),(h=f(h,512+i)).unshift(...Array(16)),o(92),i=640}for(h=f(h,i);n;)l[--n]=h[n>>2]>>>n%4*8;return t?l:l.reduce((r,e)=>r+(e>>4&&"")+e.toString(16),"")}}


await(async () => {
  let hmacKey;
  const request = async (method, url, body) => {
    const headers = { "content-type": "application/json" };
    if (navigator.userAgent.includes("gandi-desktop")) try {
      // gandi desktop
      const { token, userId } = electron.ipcRenderer.sendSync("auth:get-token");
      if (token) headers.token = token;
    } catch (e) { }
    if (hmacKey && body) {
      headers.b = Date.now().toString();
      headers.a = md5("ccw" + body + headers.b, hmacKey);
    }
    const r = await fetch(url, {
      method,
      credentials: "include",
      headers,
      body,
    });
    if (!r.ok) throw Error(`${r.status} ${r.statusText}`);
    const j = await r.json();
    if (j.status != 200) throw Error(j.msg);
    return j.body
  };
  hmacKey = await request("POST", "https://community-web.ccw.site/health/check")
    .then(body => body.reduce((p, v) => v.traceId[parseInt(v.traceId[0], 16) + 1] + p, ''));
  const encoder = new TextEncoder
    , decoder = new TextDecoder
    , bytesToHex = (bytes) => (
      bytes.toHex
        ? bytes.toHex()
        : bytes.reduce((p, v) => p + (v >> 4 && '') + v.toString(16), '')
    )
    , base64ToBytes = (
      Uint8Array.fromBase64
        ? (input) => Uint8Array.fromBase64(input)
        : (input) => Uint8Array.from(atob(input), v => v.charCodeAt())
    )
    , client_id = bytesToHex(crypto.getRandomValues(new Uint8Array(32)))
    , key = encoder.encode(client_id.slice(0, 16))
    , iv = encoder.encode("GSs0NL83MBynOzVh")
    , cipherBytes = await request("GET", `https://sso.ccw.site/oauth/authorize?state=${client_id}`)
      .then(body => base64ToBytes(body))
    , cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    )
    , code = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      cryptoKey,
      cipherBytes
    ).then(buf => decoder.decode(buf))
    , oauthBody = await request("POST", "https://sso.ccw.site/oauth/token", JSON.stringify({ code }));
  return oauthBody.token
})()
