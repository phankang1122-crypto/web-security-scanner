import express from "express";
import * as cheerio from "cheerio";
import dns from "node:dns/promises";
import net from "node:net";
import ipaddr from "ipaddr.js";

const app = express();
app.use(express.json({limit:"20kb"}));
app.use(express.static("public"));
const MAX_PAGES=80, MAX_LINKS=250, TIMEOUT=9000, MAX_BODY=1_500_000;

function isPublicAddress(address) {
  if (!ipaddr.isValid(address)) return false;
  const range=ipaddr.parse(address).range();
  return range==="unicast";
}
async function assertSafeHost(hostname) {
  if (hostname==="localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local")) throw new Error("Địa chỉ máy chủ nội bộ bị chặn");
  if (net.isIP(hostname)) {
    if (!isPublicAddress(hostname)) throw new Error("IP riêng hoặc IP đặc biệt bị chặn");
    return;
  }
  const records=await dns.lookup(hostname,{all:true,verbatim:true});
  if (!records.length || records.some(r=>!isPublicAddress(r.address))) throw new Error("Tên miền phân giải tới IP nội bộ/không công khai; đã chặn để tránh SSRF");
}
function normalizeUrl(raw, base) {
  try {
    const u=new URL(raw,base);
    if (!["http:","https:"].includes(u.protocol)) return null;
    u.hash="";
    if (u.username || u.password) return null;
    return u.href;
  } catch { return null; }
}
async function safeFetch(startUrl) {
  let current=startUrl, redirects=0;
  while (true) {
    const u=new URL(current);
    await assertSafeHost(u.hostname);
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),TIMEOUT);
    let response;
    try {
      response=await fetch(current,{method:"GET",redirect:"manual",signal:controller.signal,
        headers:{"User-Agent":"WebSecurityScanner/1.0 (authorized passive audit)","Accept":"text/html,*/*;q=0.8"}});
    } finally { clearTimeout(timer); }
    if ([301,302,303,307,308].includes(response.status) && response.headers.get("location")) {
      if (redirects++>=5) return {response,url:current,redirected:true,body:""};
      const next=normalizeUrl(response.headers.get("location"),current);
      if (!next) return {response,url:current,redirected:true,body:""};
      current=next; continue;
    }
    const len=Number(response.headers.get("content-length")||0);
    if (len>MAX_BODY) return {response,url:current,body:""};
    const type=response.headers.get("content-type")||"";
    let body="";
    if (type.includes("text/html") || type.includes("text/plain")) {
      const reader=response.body?.getReader();
      if(reader){
        const chunks=[]; let total=0;
        while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>MAX_BODY){await reader.cancel();break;}chunks.push(value);}
        body=new TextDecoder().decode(Buffer.concat(chunks));
      }
    }
    return {response,url:current,body};
  }
}
function severityFor(status) {
  if(status===404 || status===410) return ["Thấp","Liên kết không còn tồn tại hoặc đã bị xóa"];
  if(status===401 || status===403) return ["Thông tin","Trang yêu cầu quyền truy cập hoặc từ chối truy cập"];
  if(status>=500) return ["Trung bình","Máy chủ đích gặp lỗi"];
  if(status===0) return ["Trung bình","Không kết nối được, timeout hoặc lỗi DNS/TLS"];
  if(status>=400) return ["Thấp","Yêu cầu không thành công"];
  return ["Không phát hiện",""];
}
app.post("/api/scan",async(req,res)=>{
  const input=String(req.body?.url||"").trim();
  let root;
  try { root=new URL(input); if(!["http:","https:"].includes(root.protocol)) throw 0; if(root.username||root.password)throw 0; await assertSafeHost(root.hostname); }
  catch { return res.status(400).json({error:"URL không hợp lệ hoặc đích đến là địa chỉ nội bộ/không an toàn."}); }
  const rootOrigin=root.origin, queue=[root.href], seenPages=new Set(), seenLinks=new Set(), results=[];
  const pageFindings=[];
  while(queue.length && seenPages.size<MAX_PAGES && seenLinks.size<MAX_LINKS){
    const page=queue.shift(); if(seenPages.has(page))continue; seenPages.add(page);
    let fetched;
    try { fetched=await safeFetch(page); }
    catch(e){pageFindings.push({url:page,status:0,error:e.name==="AbortError"?"Hết thời gian chờ":e.message});continue;}
    const r=fetched.response, finalUrl=fetched.url;
    const headers=r.headers;
    if(new URL(finalUrl).origin===rootOrigin){
      const missing=[];
      for(const h of ["content-security-policy","strict-transport-security","x-content-type-options","referrer-policy","permissions-policy"])
        if(!headers.get(h))missing.push(h);
      pageFindings.push({url:finalUrl,status:r.status,missingHeaders:missing});
    }
    if(!fetched.body || !(headers.get("content-type")||"").includes("text/html"))continue;
    const $=cheerio.load(fetched.body);
    $("a[href],area[href],link[href],script[src],img[src],iframe[src],source[src]").each((_,el)=>{
      const raw=$(el).attr("href")||$(el).attr("src"); const target=normalizeUrl(raw,finalUrl);
      if(!target || seenLinks.has(target) || seenLinks.size>=MAX_LINKS)return;
      seenLinks.add(target);
      const u=new URL(target);
      if(u.origin===rootOrigin && !seenPages.has(target) && queue.length<MAX_PAGES)queue.push(target);
    });
  }
  // Check every discovered link, including external destinations, with strict redirect/IP protections.
  for(const link of seenLinks){
    try{
      const f=await safeFetch(link), s=f.response.status;
      const [severity,description]=severityFor(s);
      results.push({url:link,finalUrl:f.url,status:s,severity,description,redirected:f.url!==link});
    }catch(e){
      results.push({url:link,finalUrl:"",status:0,severity:"Trung bình",description:e.name==="AbortError"?"Hết thời gian chờ":e.message});
    }
  }
  res.json({root:root.href,pagesScanned:seenPages.size,linksChecked:results.length,
    broken:results.filter(x=>x.status===0||x.status>=400).length,
    results, pageFindings, limits:{maxPages:MAX_PAGES,maxLinks:MAX_LINKS}});
});
const port=process.env.PORT||3000;
app.listen(port,()=>console.log(`Web Security Scanner listening on ${port}`));