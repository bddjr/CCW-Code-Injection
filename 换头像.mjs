/** @license https://github.com/bddjr/tinyhmacmd5/blob/HEAD/LICENSE */
{let r="length",e=16,n=2**32,t=1732584193,o=271733878,a=~t,f=~o,u=Math,i=u.floor,l=[738695,669989,770404,703814],d=Array(64),s=(s,v)=>{var y,c,g,h,A,w=0,b=i((v+64)/512)*e+14,m=[t,f,a,o],p=[...m],x=r=>m[3&++A];for(s[i(v/32)]|=128<<v%32,s[b]=0|v,s[b+1]=0|v/n;w<s[r];w+=e){for(A=b=0;b<64;A-=6)m[3&A]=(c=x(),g=x(),h=x(),0|((c=((y=b>>4)?y>1?y>2?g^(c|~h):c^g^h:c&h|g&~h:c&g|~c&h)+(0|s[w+(b*(29521>>4*y)+(1296>>4*y)&15)])+(g=l[y]>>b%4*5&31,d[b++]??=0|n*u.abs(u.sin(b)))+x())<<g|c>>>32-g)+x());for(A=4;A;)p[--A]=m[A]=0|p[A]+m[A]}return m},v=e=>{for(var n=e[r],t=[];n;)t[i(--n/4)]|=e[n]<<n%4*8;return t},y=r=>"string"==typeof r?(new TextEncoder).encode(r):r;var md5=(n,t,o)=>{var a,f=v(n=y(n)),u=8*n[r],i=e,l=new Uint8Array(e),d=r=>{for(f.unshift(...Array(e));i;)f[--i]=16843009*r^a[i];i=e};for(null!=t&&((a=v(t=y(t)))[r]>e&&(a=s(a,8*t[r])),d(54),f=s(f,512+u),d(92),u=640),f=s(f,u);i;)l[--i]=f[i>>2]>>>i%4*8;return o?l:l.reduce((r,n)=>r+(n>>4&&"")+n.toString(e),"")}}

// 换头像
await fetch("https://community-web.ccw.site/health/check", {
  method: "POST",
  credentials: "include"
}).then(r => {
  if (!r.ok) throw Error(`${r.status} ${r.statusText}`);
  return r.json()
}).then(j => {
  if (j.status != 200) throw Error(j.msg);
  const hmacKey = j.body
    .map(({ traceId }) => traceId[parseInt(traceId[0], 16) + 1])
    .reverse()
    .join("")
  const body = JSON.stringify({
    // 头像的文件地址，注意结尾应该有参数 ?x-oss-process=0 防止前端不渲染svg或者压缩图片
    avatar: "https://m.ccw.site/user_projects_assets/11e4d54652fe811d8ae24371393c95c2.svg?x-oss-process=0",
  })
  const b = Date["now"]().toString()
  const a = md5("ccw" + body + b, hmacKey);
  return fetch("https://community-web.ccw.site/students/update", {
    method: "POST",
    credentials: "include",
    headers: { a, b, "content-type": "application/json" },
    body,
  })
})