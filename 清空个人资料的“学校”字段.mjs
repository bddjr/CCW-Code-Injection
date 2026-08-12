/** @license https://bddjr.github.io/tinyhmacmd5/lic */
{let r=1732584193,e=271733878,n=~r,t=~e,o=2**32,f=Math,a=f.floor,l=r=>16*a((r+8)/64)+16,i=[],u=(u,d,h=0,c=l(d),g,s,w,y,A=[r,t,n,e],v=[...A])=>{for(u[c-1]=0|8*d/o,u[c-2]=0|8*d,u[a(d/4)]|=128<<d%4*8;h<u.length;h+=16){for(y=c=0;c<64;)A[3&y]=0|((g=0|(g=A[3&++y],s=A[3&++y],w=A[3&++y],((d=c>>4<<2)?d>4?d>8?s^(g|~w):g^s^w:g&w|s&~w:g&s|~g&w)+(0|u[h+(c*(29521>>d)+(1296>>d)&15)])+(s=31&"',16%).4$+07&*/5".charCodeAt(d+c%4),i[63-c++]??=0|o*f.abs(f.sin(c)))+A[y+1&3]))<<s|g>>>32-s)+A[y+2&3];for(y=4;y;)v[--y]=A[y]=0|v[y]+A[y]}return A},d=(r,e,n=("string"==typeof r?r=(new TextEncoder).encode(r):r).length,t=new Int32Array(l(4*e+n)),o=0)=>{for(;o<n;)t[e++]=r[o++]|r[o++]<<8|r[o++]<<16|r[o++]<<24;return[t,n]};var md5=(r,e,n)=>{var t=16,o=null!=e,[f,a]=d(r,o*t),l=new Uint8Array(t);if(o){let[r,n]=d(e,0),o=[];for(n>64&&(r=u(r,n));t;)f[--t]=909522486^r[t],o[t]=1549556828^r[t];t=16,(f=u(f,64+a)).unshift(...o),a=80}for(f=u(f,a);t;)l[--t]=f[t>>2]>>>t%4*8;return n?l:l.reduce((r,e)=>r+(e>>4&&"")+e.toString(16),"")}}

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