/** @license https://bddjr.github.io/tinyhmacmd5/lic */
{let r=[],n=Math,t=n.floor,e=r=>16*t((r+72)/64),o=(o,f,a=0,l=e(f),c=1732584193,i=271733878,d,g,h=[c,~i,~c,i],u=[...h])=>{for(o[l-1]=0|f/2**29,o[t(f/4)]|=128<<(o[l-2]=f<<3);a<o.length;){for(l=0;l<64;)h[g&=3]=0|((i=0|h[g]+(c=h[3&++g],i=h[3&++g],d=h[3&++g],(f=l>>4<<2)?f>4?f>8?i^(c|~d):c^i^d:c&d|i&~d:c&i|~c&d)+(0|o[a+(l*(29521>>f)+(1296>>f)&15)])+(d="',16%).4$+07&*/5".charCodeAt(3&l|f),r[63-l++]??=0|2**32*n.abs(n.sin(l))))<<d|i>>>64-d)+c;for(;g;a+=4)u[--g]=h[g]=0|u[g]+h[g]}return h},f=(r,n,t=("string"==typeof r?r=(new TextEncoder).encode(r):r).length,o=new Int32Array(e(4*n+t)),f=0)=>{for(;f<t;)o[n++]=r[f++]|r[f++]<<8|r[f++]<<16|r[f++]<<24;return[o,t]};var md5=(r,n,t)=>{var e=16,a=null!=n,[l,c]=f(r,a*e),i=[],d=t?new Uint8Array(e):"";if(a){let[r,t]=f(n,0);for(t>64&&(r=o(r,t));e;)i[--e]=1785358954^(l[e]=909522486^r[e]);e=16,l=i.concat(o(l,64+c)),c=80}for(l=o(l,c);e;t?d[e]=i:d=(i>>4&&"")+i.toString(16)+d)i=l[--e>>2]>>8*e&255;return d}}

// 换头像
await fetch("https://community-web.ccw.site/health/check", {
  method: "POST",
  credentials: "include"
}).then(r => {
  if (!r.ok) throw Error(`${r.status} ${r.statusText}`);
  return r.json()
}).then(j => {
  if (j.status != 200) throw Error(j.msg);
  const hmacKey = j.body.reduce((p, v) => v.traceId[parseInt(v.traceId[0], 16) + 1] + p, '')
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