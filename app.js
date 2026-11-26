const $=id=>document.getElementById(id);let last=null;
$("scan").onclick=async()=>{const url=$("url").value.trim();if(!url)return $("status").textContent="Hãy nhập địa chỉ website.";
$("scan").disabled=true;$("status").textContent="Đang quét... Có thể mất vài phút tùy số lượng liên kết.";
$("summary").classList.add("hidden");$("findings").classList.add("hidden");$("headers").classList.add("hidden");
try{const r=await fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});const data=await r.json();if(!r.ok)throw Error(data.error||"Không thể quét");last=data;
$("summary").innerHTML=`<div class="stat">Trang đã quét<strong>${data.pagesScanned}</strong></div><div class="stat">Link đã kiểm tra<strong>${data.linksChecked}</strong></div><div class="stat">Link có lỗi<strong class="danger">${data.broken}</strong></div>`;$("summary").classList.remove("hidden");
render(data.results);$("findings").classList.remove("hidden");
const all=data.pageFindings.flatMap(x=>(x.missingHeaders||[]).map(h=>({url:x.url,header:h})));
$("headerRows").innerHTML=all.length?all.map(x=>`<p><span class="warn">Thiếu ${esc(x.header)}</span> — ${esc(x.url)}</p>`).join(""):"Không phát hiện header bị thiếu trên các trang HTML đã kiểm tra.";
$("headers").classList.remove("hidden");$("status").textContent="Hoàn tất. Lưu ý: đây là kiểm tra thụ động, không phải chứng nhận an toàn.";
}catch(e){$("status").textContent=e.message}finally{$("scan").disabled=false}};
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function render(items){const q=$("filter").value.toLowerCase();$("rows").innerHTML=items.filter(x=>(x.url+" "+x.status+" "+x.description).toLowerCase().includes(q)).map(x=>`<tr><td>${esc(x.url)}</td><td>${x.status||"Không kết nối"}</td><td><span class="pill ${x.severity==="Trung bình"?"warn":x.status>=400?"danger":"good"}">${esc(x.severity)}</span></td><td>${esc(x.description||"Không phát hiện lỗi HTTP")}${x.redirected?" (có chuyển hướng)":""}</td></tr>`).join("")||"<tr><td colspan='4'>Không có kết quả phù hợp.</td></tr>"}
$("filter").oninput=()=>last&&render(last.results);
$("csv").onclick=()=>{if(!last)return;const rows=[["URL","Final URL","HTTP","Severity","Description"],...last.results.map(x=>[x.url,x.finalUrl,x.status,x.severity,x.description])];const csv=rows.map(r=>r.map(v=>'"'+String(v??"").replace(/"/g,'""')+'"').join(",")).join("\n");const a=document.createElement("a");a.href=URL.createObjectURL(new Blob(["\ufeff"+csv],{type:"text/csv;charset=utf-8"}));a.download="web-security-report.csv";a.click();URL.revokeObjectURL(a.href)};