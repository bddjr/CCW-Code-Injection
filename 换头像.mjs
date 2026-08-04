/** @license https://github.com/bddjr/tinyhmacmd5/blob/HEAD/LICENSE */
{let r="length",e=16,n=2**32,t=Math,o=t.floor,a=(r,e)=>0|(0|r)+(0|e),f=(r,e)=>r<<e|r>>>32-e,l=(r,e,n,t,o,l)=>a(f(a(e,r)+a(t,l),o),n),i=(r,e,n,t,o,a,f)=>l(e&n|~e&t,r,e,o,a,f),u=(r,e,n,t,o,a,f)=>l(e&t|n&~t,r,e,o,a,f),s=(r,e,n,t,o,a,f)=>l(e^n^t,r,e,o,a,f),c=(r,e,n,t,o,a,f)=>l(n^(e|~t),r,e,o,a,f),d=[],v=(f,l)=>{var v,g,h,w,y,b=0,m=1732584193,p=271733878,x=~m,A=~p,E=o((l+64)/512)*e+14,M=r=>d[y++]??=0|n*t.abs(t.sin(y));for(f[o(l/32)]|=128<<l%32,f[E]=0|l,f[E+1]=0|l/n;b<f[r];p=a(p,w)){let[r,n,t,o,l,d,E,S,T,U,j,k,q,z,B,C]=f.slice(b,b+=e);v=m,g=A,h=x,w=p,y=0,m=i(m,A,x,p,r,7,M()),p=i(p,m,A,x,n,12,M()),x=i(x,p,m,A,t,17,M()),A=i(A,x,p,m,o,22,M()),m=i(m,A,x,p,l,7,M()),p=i(p,m,A,x,d,12,M()),x=i(x,p,m,A,E,17,M()),A=i(A,x,p,m,S,22,M()),m=i(m,A,x,p,T,7,M()),p=i(p,m,A,x,U,12,M()),x=i(x,p,m,A,j,17,M()),A=i(A,x,p,m,k,22,M()),m=i(m,A,x,p,q,7,M()),p=i(p,m,A,x,z,12,M()),x=i(x,p,m,A,B,17,M()),A=i(A,x,p,m,C,22,M()),m=u(m,A,x,p,n,5,M()),p=u(p,m,A,x,E,9,M()),x=u(x,p,m,A,k,14,M()),A=u(A,x,p,m,r,20,M()),m=u(m,A,x,p,d,5,M()),p=u(p,m,A,x,j,9,M()),x=u(x,p,m,A,C,14,M()),A=u(A,x,p,m,l,20,M()),m=u(m,A,x,p,U,5,M()),p=u(p,m,A,x,B,9,M()),x=u(x,p,m,A,o,14,M()),A=u(A,x,p,m,T,20,M()),m=u(m,A,x,p,z,5,M()),p=u(p,m,A,x,t,9,M()),x=u(x,p,m,A,S,14,M()),A=u(A,x,p,m,q,20,M()),m=s(m,A,x,p,d,4,M()),p=s(p,m,A,x,T,11,M()),x=s(x,p,m,A,k,e,M()),A=s(A,x,p,m,B,23,M()),m=s(m,A,x,p,n,4,M()),p=s(p,m,A,x,l,11,M()),x=s(x,p,m,A,S,e,M()),A=s(A,x,p,m,j,23,M()),m=s(m,A,x,p,z,4,M()),p=s(p,m,A,x,r,11,M()),x=s(x,p,m,A,o,e,M()),A=s(A,x,p,m,E,23,M()),m=s(m,A,x,p,U,4,M()),p=s(p,m,A,x,q,11,M()),x=s(x,p,m,A,C,e,M()),A=s(A,x,p,m,t,23,M()),m=c(m,A,x,p,r,6,M()),p=c(p,m,A,x,S,10,M()),x=c(x,p,m,A,B,15,M()),A=c(A,x,p,m,d,21,M()),m=c(m,A,x,p,q,6,M()),p=c(p,m,A,x,o,10,M()),x=c(x,p,m,A,j,15,M()),A=c(A,x,p,m,n,21,M()),m=c(m,A,x,p,T,6,M()),p=c(p,m,A,x,C,10,M()),x=c(x,p,m,A,E,15,M()),A=c(A,x,p,m,z,21,M()),m=c(m,A,x,p,l,6,M()),p=c(p,m,A,x,k,10,M()),x=c(x,p,m,A,t,15,M()),A=c(A,x,p,m,U,21,M()),m=a(m,v),A=a(A,g),x=a(x,h)}return[m,A,x,p]},g=e=>{for(var n=e[r],t=[];n;)t[o(--n/4)]|=e[n]<<n%4*8;return t},h=r=>"string"==typeof r?(new TextEncoder).encode(r):r;var md5=(n,t,o)=>{var a,f=g(n=h(n)),l=8*n[r],i=e,u=new Uint8Array(e),s=r=>{for(;i;)f.unshift(r^a[--i]);i=e};for(null!=t&&((a=g(t=h(t)))[r]>e&&(a=v(a,8*t[r])),s(909522486),f=v(f,512+l),s(1549556828),l=640),f=v(f,l);i;)u[--i]=f[i>>2]>>>i%4*8;return o?u:u.reduce((r,n)=>r+(n>>4&&"")+n.toString(e),"")}}

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