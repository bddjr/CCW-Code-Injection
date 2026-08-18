// ccw oauth 创建新会话并返回 token
// ctrl+shift+i 打开 devtools ，在控制台粘贴然后 enter

/** @license https://bddjr.github.io/tinyhmacmd5/lic */
{let r=1732584193,n=271733878,t=[],e=Math,o=e.floor,f=r=>16*o((r+72)/64),a=(a,l,c=0,i=f(l),d,g,h,u,s=[r,~n,~r,n],w=[...s])=>{for(a[i-1]=0|l/2**29,a[i-2]=0|8*l,a[o(l/4)]|=128<<8*l;c<a.length;){for(i=0;i<64;)s[u&=3]=0|((d=0|(d=s[3&++u],g=s[3&++u],h=s[3&++u],((l=i>>4<<2)?l>4?l>8?g^(d|~h):d^g^h:d&h|g&~h:d&g|~d&h)+(0|a[c+(i*(29521>>l)+(1296>>l)&15)])+(g="',16%).4$+07&*/5".charCodeAt(l+i%4),t[63-i++]??=0|2**32*e.abs(e.sin(i)))+s[u+1&3]))<<g|d>>>64-g)+s[u+2&3];for(;u;c+=4)w[--u]=s[u]=0|w[u]+s[u]}return s},l=(r,n,t=("string"==typeof r?r=(new TextEncoder).encode(r):r).length,e=new Int32Array(f(4*n+t)),o=0)=>{for(;o<t;)e[n++]=r[o++]|r[o++]<<8|r[o++]<<16|r[o++]<<24;return[e,t]};var md5=(r,n,t)=>{var e=16,o=null!=n,[f,c]=l(r,o*e),i=[],d=t?new Uint8Array(e):"";if(o){let[r,t]=l(n,0);for(t>64&&(r=a(r,t));e;)i[--e]=1785358954^(f[e]=909522486^r[e]);e=16,f=i.concat(a(f,64+c)),c=80}for(f=a(f,c);e;t?d[e]=i:d=(i>>4&&"")+i.toString(16)+d)i=f[--e>>2]>>8*e&255;return d}}


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
