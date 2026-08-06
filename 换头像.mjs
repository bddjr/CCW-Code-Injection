/** @license https://github.com/bddjr/tinyhmacmd5/blob/HEAD/LICENSE */
{let r="length",e=16,n=2**32,t=Array,o=Math,a=o.floor,f=[(r,e,n)=>r&e|~r&n,(r,e,n)=>r&n|e&~n,(r,e,n)=>r^e^n,(r,e,n)=>e^(r|~n)],u=t(64),i=(i,l)=>{var d,s,v,c,g,h,y,w,A=0,b=1732584193,m=271733878,p=~b,x=~m,E=a((l+64)/512)*e+14,M=t(e),S=(r,e,t,a)=>0|((y=e+r+(y=E++*(7&3817>>3*h)+(7&328>>3*h)&15,h?M[y]:M[y]=0|i[A++])+(u[g++]??=0|n*o.abs(o.sin(g))))<<a|y>>>32-a)+t,T=(r,n,t,o)=>{for(w=f[h],E=0;E<e;)b=S(w(x,p,m),b,x,r),m=S(w(b,x,p),m,b,n),p=S(w(m,b,x),p,m,t),x=S(w(p,m,b),x,p,o);h++};for(i[a(l/32)]|=128<<l%32,i[E]=0|l,i[E+1]=0|l/n;A<i[r];m=0|m+c)d=b,s=x,v=p,c=m,g=h=0,T(7,12,17,22),T(5,9,14,20),T(4,11,e,23),T(6,10,15,21),b=0|b+d,x=0|x+s,p=0|p+v;return[b,x,p,m]},l=e=>{for(var n=e[r],t=[];n;)t[a(--n/4)]|=e[n]<<n%4*8;return t},d=r=>"string"==typeof r?(new TextEncoder).encode(r):r;var md5=(n,o,a)=>{var f,u=l(n=d(n)),s=8*n[r],v=e,c=new Uint8Array(e),g=r=>{for(u.unshift(...t(e));v;)u[--v]=r^f[v];v=e};for(null!=o&&((f=l(o=d(o)))[r]>e&&(f=i(f,8*o[r])),g(909522486),u=i(u,512+s),g(1549556828),s=640),u=i(u,s);v;)c[--v]=u[v>>2]>>>v%4*8;return a?c:c.reduce((r,n)=>r+(n>>4&&"")+n.toString(e),"")}}

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