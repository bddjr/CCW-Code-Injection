/** @license https://bddjr.github.io/tinyhmacmd5/lic */
{let r=1732584193,n=271733878,t=[],e=Math,o=e.floor,f=r=>16*o((r+72)/64),a=(a,l,c=0,i=f(l),d,g,h,u,s=[r,~n,~r,n],w=[...s])=>{for(a[i-1]=0|l/2**29,a[i-2]=0|8*l,a[o(l/4)]|=128<<8*l;c<a.length;){for(i=0;i<64;)s[u&=3]=0|((d=0|(d=s[3&++u],g=s[3&++u],h=s[3&++u],((l=i>>4<<2)?l>4?l>8?g^(d|~h):d^g^h:d&h|g&~h:d&g|~d&h)+(0|a[c+(i*(29521>>l)+(1296>>l)&15)])+(g="',16%).4$+07&*/5".charCodeAt(l+i%4),t[63-i++]??=0|2**32*e.abs(e.sin(i)))+s[u+1&3]))<<g|d>>>64-g)+s[u+2&3];for(;u;c+=4)w[--u]=s[u]=0|w[u]+s[u]}return s},l=(r,n,t=("string"==typeof r?r=(new TextEncoder).encode(r):r).length,e=new Int32Array(f(4*n+t)),o=0)=>{for(;o<t;)e[n++]=r[o++]|r[o++]<<8|r[o++]<<16|r[o++]<<24;return[e,t]};var md5=(r,n,t)=>{var e=16,o=null!=n,[f,c]=l(r,o*e),i=[],d=t?new Uint8Array(e):"";if(o){let[r,t]=l(n,0);for(t>64&&(r=a(r,t));e;)i[--e]=1785358954^(f[e]=909522486^r[e]);e=16,f=i.concat(a(f,64+c)),c=80}for(f=a(f,c);e;t?d[e]=i:d=(i>>4&&"")+i.toString(16)+d)i=f[--e>>2]>>8*e&255;return d}}

// 清空个人资料的“学校”字段
await fetch("https:/\/community-web.ccw.site/health/check", {
  method: "POST",
  credentials: "include"
}).then(r => {
  if (!r.ok) throw Error(`${r.status} ${r.statusText}`);
  return r.json()
}).then(j => {
  if (j.status != 200) throw Error(j.msg);
  const hmacKey = j.body.reduce((p, v) => v.traceId[parseInt(v.traceId[0], 16) + 1] + p, '')
    , body = `{"school":""}`
    , b = Date["now"]().toString()
    , a = md5("ccw" + body + b, hmacKey);
  return fetch("https:/\/community-web.ccw.site/students/update", {
    method: "POST",
    credentials: "include",
    headers: { a, b, "content-type": "application/json" },
    body,
  })
})