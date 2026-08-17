// ccw oauth 创建新会话并返回 token
// ctrl+shift+i 打开 devtools ，在控制台粘贴然后 enter

/** @license https://bddjr.github.io/tinyhmacmd5/lic */
{let r=1732584193,e=271733878,n=~r,t=~e,o=2**32,f=Math,a=f.floor,l=r=>16*a((r+8)/64)+16,c=[],d=(d,i,u=0,g=l(i),h,s,w,y,A=[r,t,n,e],v=[...A])=>{for(d[g-1]=0|8*i/o,d[g-2]=0|8*i,d[a(i/4)]|=128<<i%4*8;u<d.length;u+=16){for(y=g=0;g<64;)A[3&y]=0|((h=0|(h=A[3&++y],s=A[3&++y],w=A[3&++y],((i=g>>4<<2)?i>4?i>8?s^(h|~w):h^s^w:h&w|s&~w:h&s|~h&w)+(0|d[u+(g*(29521>>i)+(1296>>i)&15)])+(s="',16%).4$+07&*/5".charCodeAt(i+g%4),c[63-g++]??=0|o*f.abs(f.sin(g)))+A[y+1&3]))<<s|h>>>64-s)+A[y+2&3];for(y=4;y;)v[--y]=A[y]=0|v[y]+A[y]}return A},i=(r,e,n=("string"==typeof r?r=(new TextEncoder).encode(r):r).length,t=new Int32Array(l(4*e+n)),o=0)=>{for(;o<n;)t[e++]=r[o++]|r[o++]<<8|r[o++]<<16|r[o++]<<24;return[t,n]};var md5=(r,e,n)=>{var t=16,o=null!=e,[f,a]=i(r,o*t),l=new Uint8Array(t);if(o){let[r,n]=i(e,0),o=[];for(n>64&&(r=d(r,n));t;)o[--t]=1785358954^(f[t]=909522486^r[t]);t=16,f=o.concat(d(f,64+a)),a=80}for(f=d(f,a);t;)l[--t]=f[t>>2]>>>t%4*8;return n?l:l.reduce((r,e)=>r+(e>>4&&"")+e.toString(16),"")}}


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
