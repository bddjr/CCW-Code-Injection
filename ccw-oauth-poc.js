// ccw oauth 创建新会话并返回 token
// ctrl+shift+i 打开 devtools ，在控制台粘贴然后 enter

/** @license https://bddjr.github.io/tinyhmacmd5/lic */
{let r=[],n=Math,t=n.floor,e=r=>16*t((r+72)/64),o=(o,f,a=0,l=e(f),c=1732584193,i=271733878,d,g,h=[c,~i,~c,i],u=[...h])=>{for(o[l-1]=0|f/2**29,o[t(f/4)]|=128<<(o[l-2]=f<<3);a<o.length;){for(l=0;l<64;)h[g&=3]=0|((i=0|h[g]+(c=h[3&++g],i=h[3&++g],d=h[3&++g],(f=l>>4<<2)?f>4?f>8?i^(c|~d):c^i^d:c&d|i&~d:c&i|~c&d)+(0|o[a+(l*(29521>>f)+(1296>>f)&15)])+(d="',16%).4$+07&*/5".charCodeAt(3&l|f),r[63-l++]??=0|2**32*n.abs(n.sin(l))))<<d|i>>>64-d)+c;for(;g;a+=4)u[--g]=h[g]=0|u[g]+h[g]}return h},f=(r,n,t=("string"==typeof r?r=(new TextEncoder).encode(r):r).length,o=new Int32Array(e(4*n+t)),f=0)=>{for(;f<t;)o[n++]=r[f++]|r[f++]<<8|r[f++]<<16|r[f++]<<24;return[o,t]};var md5=(r,n,t)=>{var e=16,a=null!=n,[l,c]=f(r,a*e),i=[],d=t?new Uint8Array(e):"";if(a){let[r,t]=f(n,0);for(t>64&&(r=o(r,t));e;)i[--e]=1785358954^(l[e]=909522486^r[e]);e=16,l=i.concat(o(l,64+c)),c=80}for(l=o(l,c);e;t?d[e]=i:d=(i>>4&&"")+i.toString(16)+d)i=l[--e>>2]>>8*e&255;return d}}


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
