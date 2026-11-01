// AnyPS5-inspired R2O progress map; standard Node.js only.
import {readFileSync,writeFileSync,mkdirSync,existsSync} from "node:fs";
import {execFileSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import {resolve} from "node:path";
const CATS=["Datapath","Classifier / TLS","Discovery","QUIC / HTTP3","Discord RTC","Telegram","WebPanel","Firewall / PPE","Release / ABI"];
const COLORS={"verified":"#36c989","partial":"#e6b45d","implemented":"#819bf8","unknown":"#65758c"};
function esc(v){return String(v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}

function groupFor(t){
 if(/^Discord/.test(t))return "Discord RTC";
 if(/^(Telegram|Keenetic Meta DNS)/.test(t))return "Telegram";
 if(/^Панель/.test(t))return "WebPanel";
 if(/^(Firewall|Аппаратное ускорение PPE)/.test(t))return "Firewall / PPE";
 if(/^(Install\/update|ABI\/QEMU)/.test(t))return "Release / ABI";
 if(/^(QUIC|Остальные QUIC)/.test(t))return "QUIC / HTTP3";
 if(/^(Scheduler|Discovery|ACK →|JSON catalog|Полный автоматический цикл|Кадр управления|HTTP search)/.test(t))return "Discovery";
 if(/^(Raw-|Подтверждение базового CLEAR|CLEAR|Базовые transport|Классификатор|TCP measurement|Потолок classifier|TLS|ECH)/.test(t))return "Classifier / TLS";
 return "Datapath";
}

function parse(source){
 const part=source.split(/^## Матрица\s*$/m)[1]?.split(/^## /m)[0];
 if(!part)throw Error("No Matrix section");
 const rows=part.split(/\r?\n/).filter(s=>s.startsWith("| ")&&!/^\|\s*(?:---|Контракт и вес)/.test(s));
 const items=rows.map((line,i)=>{
  const c=line.split("|").slice(1,-1).map(x=>x.trim());if(c.length!==5)throw Error("Bad columns "+(i+1));
  const m=c[0].match(/^(.*?)\s+\((\d+)\)$/);if(!m)throw Error("No weight "+c[0]);
  const weight=Number(m[2]),points=Number(c[4]),status=/^(Доказанно эквивалентно|Эквивалентно)$/.test(c[2])?"verified":/^Частично/.test(c[2])?"partial":/^Реализовано/.test(c[2])?"implemented":"unknown";
  if(!Number.isInteger(points)||!Number.isInteger(weight)||points<0||points>weight||(status==="verified"?points!==weight:points!==0))throw Error("Invalid score "+c[0]);
  return {id:i+1,name:m[1],weight,points,status,statusLabel:c[2],group:groupFor(m[1]),mapping:c[1],evidence:c[3].slice(0,600)};
 });
 if(!items.length)throw Error("No rows");
 const groups=CATS.map(name=>{const cards=items.filter(v=>v.group===name);return {name,items:cards,weight:cards.reduce((a,v)=>a+v.weight,0),points:cards.reduce((a,v)=>a+v.points,0)}}).filter(g=>g.items.length);
 const weight=items.reduce((a,v)=>a+v.weight,0),points=items.reduce((a,v)=>a+v.points,0);
 return {source:"docs/functional-parity-matrix.md",date:source.match(/Аудит среза\s+`(\d{4}-\d{2}-\d{2})`/)?.[1]||"",weight,points,percent:+(points/weight*100).toFixed(2),total:items.length,counts:{verified:items.filter(i=>i.status==="verified").length,partial:items.filter(i=>i.status==="partial").length,implemented:items.filter(i=>i.status==="implemented").length,unknown:items.filter(i=>i.status==="unknown").length},groups,items};
}

function svg(d){
 const h=175+Math.ceil(d.groups.length/2)*112+55,s=[`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1100 ${h}" width="1100" height="${h}" role="img" aria-label="R2O parity ${d.percent}%">`,`<rect width="1100" height="${h}" rx="20" fill="#0c121e"/>`,`<text x="36" y="48" fill="#edf7ff" font-family="Arial,sans-serif" font-size="29" font-weight="700">R2O / D2O · Functional parity</text>`,`<text x="37" y="98" fill="#36c989" font-family="Arial,sans-serif" font-size="42" font-weight="700">${d.percent.toFixed(2)}%</text>`,`<text x="230" y="93" fill="#9bafc3" font-family="Arial,sans-serif" font-size="18">${d.points} / ${d.weight} verified points</text>`,`<rect x="37" y="113" width="1024" height="11" rx="5" fill="#273245"/><rect x="37" y="113" width="${(1024*d.points/d.weight).toFixed(1)}" height="11" rx="5" fill="#36c989"/>`,`<text x="38" y="147" fill="#90a5b8" font-family="Arial,sans-serif" font-size="13">${d.total} contracts · ${d.counts.verified} verified · ${d.counts.partial} partial · ${d.counts.implemented} implemented</text>`];
 d.groups.forEach((g,i)=>{
  const x=35+(i%2)*528,y=163+Math.floor(i/2)*112;
  s.push(`<rect x="${x}" y="${y}" width="510" height="100" rx="12" fill="#152030" stroke="#2c3a4d"/>`);
  s.push(`<text x="${x+17}" y="${y+25}" fill="#e8f1fa" font-family="Arial,sans-serif" font-size="17" font-weight="700">${esc(g.name)}</text><text x="${x+493}" y="${y+25}" text-anchor="end" fill="#9bb0c5" font-family="Arial,sans-serif" font-size="13">${g.points}/${g.weight}</text>`);
  g.items.forEach((c,j)=>{const rx=x+17+(j%12)*37,ry=y+39+Math.floor(j/12)*28;s.push(`<rect x="${rx}" y="${ry}" width="29" height="22" rx="5" fill="${COLORS[c.status]}"><title>${esc(c.name)}: ${esc(c.statusLabel)} (${c.points}/${c.weight})</title></rect>`)});
  s.push(`<text x="${x+492}" y="${y+87}" text-anchor="end" fill="#8298aa" font-family="Arial,sans-serif" font-size="12">${g.items.length} contracts</text>`);
 });
 s.push(`<text x="37" y="${h-22}" fill="#89a0b6" font-family="Arial,sans-serif" font-size="13">Green = verified · Amber = partial · Blue = implemented only · Gray = unverified</text></svg>`);return s.join("\n")+"\n";
}

function badge(d,type){
 const name=type==="score"?"parity":"contracts",detail=type==="score"?`${d.percent.toFixed(2)}%  ${d.points}/${d.weight}`:`${d.counts.verified}/${d.total} verified`,w=type==="score"?246:217,b=type==="score"?78:85;
 return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} 28" width="${w}" height="28" role="img" aria-label="${esc(name+" "+detail)}"><rect width="${w}" height="28" rx="5" fill="#243146"/><path d="M${b} 0 H${w-5} Q${w} 0 ${w} 5 V23 Q${w} 28 ${w-5} 28 H${b}Z" fill="#217851"/><g fill="#ffffff" font-size="13" font-family="Arial,sans-serif"><text x="${b/2}" y="18.5" text-anchor="middle">${name}</text><text x="${b+(w-b)/2}" y="18.5" text-anchor="middle">${esc(detail)}</text></g></svg>\n`;
}

function html(d){
 const cards=d.groups.map(g=>`<section class="group"><header><strong>${esc(g.name)}</strong><small>${g.points}/${g.weight} баллов</small></header><div class="tiles">${g.items.map(c=>`<button class="tile ${c.status}" data-id="${c.id}" title="${esc(c.name)} — ${esc(c.statusLabel)}"></button>`).join("")}</div><small>${g.items.length} контрактов</small></section>`).join("");
 return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>R2O · Progress</title><style>
 :root{color-scheme:dark}*{box-sizing:border-box}body{font:15px Inter,system-ui,Segoe UI,sans-serif;color:#eaf2fb;background:radial-gradient(ellipse at 20% -15%,#194132 0,transparent 48%),#0c121e;margin:0}main{max-width:1150px;margin:auto;padding:35px 25px 75px}a{color:#62e0a7}a:hover{color:#b1ffcf}.top{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}.logo{font-size:20px;font-weight:800}.nav{display:flex;gap:22px}h1{font-size:clamp(30px,5vw,53px);margin:40px 0 7px;letter-spacing:-1.4px}p{color:#a6b7ca;line-height:1.55}.score{font-size:clamp(52px,9vw,90px);font-weight:800;color:#36c989;letter-spacing:-3px}.lead{display:flex;justify-content:space-between;align-items:end;gap:15px;flex-wrap:wrap}.bar{height:14px;background:#273449;border-radius:20px;overflow:hidden;margin:15px 0 25px}.bar b{display:block;background:linear-gradient(90deg,#238b61,#44d99b);height:100%;width:${d.percent}%}.stats{display:flex;gap:12px;flex-wrap:wrap}.stat{min-width:120px;background:#162233;border:1px solid #2a384c;border-radius:11px;padding:12px 16px}.stat b{font-size:24px;display:block}.stat small,small{color:#91a6bc}.legend{display:flex;flex-wrap:wrap;gap:17px;margin:29px 0 16px;color:#a8bace}.legend span:before{content:"";width:10px;height:10px;display:inline-block;border-radius:3px;background:var(--c);margin-right:6px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.group{border:1px solid #2b394c;border-radius:13px;background:#162233;padding:18px;min-height:140px}.group header{display:flex;justify-content:space-between;gap:10px}.tiles{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0 14px}.tile{width:30px;height:23px;border:none;border-radius:5px;cursor:pointer;transition:.15s transform}.tile:hover,.tile:focus-visible{transform:translateY(-4px);outline:2px solid white;outline-offset:2px}.verified{background:#36c989!important}.partial{background:#e6b45d!important}.implemented{background:#819bf8!important}.unknown{background:#65758c!important}.panel{background:#162233;border:1px solid #2b394c;border-radius:13px;padding:20px;margin:23px 0}.panel h2{margin:0 0 10px;font-size:18px}.panel div{line-height:1.5;overflow-wrap:anywhere}.controls{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}input,select{font:inherit;border:1px solid #34445a;background:#121c2b;color:#edf6ff;border-radius:8px;padding:11px}input{flex:1;min-width:220px}.row{border-bottom:1px solid #253246;padding:12px 5px;display:flex;align-items:flex-start;gap:12px;cursor:pointer}.dot{display:block;margin-top:5px;min-width:10px;height:10px;border-radius:2px}.row-content{flex:1}.row-content strong{display:block;font-size:14px}.row-content small{display:block;margin-top:5px}.end{font-size:13px;color:#9eb0c4}.footer{margin-top:38px;font-size:12px;color:#849bb0}@media(max-width:720px){.grid{grid-template-columns:1fr}main{padding:24px 14px}.nav{gap:10px}}
 </style></head><body><main><div class="top"><span class="logo">r2o <span style="color:#40d592">/ progress</span></span><div class="nav"><a href="https://github.com/t0fox/r2o">GitHub</a><a href="history.html">История</a><a href="https://github.com/t0fox/r2o/blob/main/docs/functional-parity-matrix.md">Матрица</a></div></div><h1>Functional parity</h1><p>Верифицированный перенос поведения D2O на Rust. Квадраты отражают доказанные контракты, а не количество строк Rust-кода.</p><div class="lead"><div><div class="score">${d.percent.toFixed(2)}%</div><small>${d.points} из ${d.weight} взвешенных баллов</small></div><small>Срез: ${esc(d.date)} · ${d.total} контрактов</small></div><div class="bar"><b></b></div><div class="stats"><div class="stat"><b>${d.counts.verified}</b><small>Доказано</small></div><div class="stat"><b>${d.counts.partial}</b><small>Частично</small></div><div class="stat"><b>${d.counts.implemented}</b><small>Реализовано</small></div><div class="stat"><b>${d.counts.unknown}</b><small>Не проверено</small></div></div><div class="legend"><span style="--c:#36c989">Доказано</span><span style="--c:#e6b45d">Частично</span><span style="--c:#819bf8">Реализовано</span><span style="--c:#65758c">Не проверено</span></div><div class="grid">${cards}</div><div id="detail" class="panel" aria-live="polite"><h2>Выберите квадрат</h2><div>Нажмите на ячейку, чтобы посмотреть контракт и подтверждающие проверки.</div></div><div class="controls"><input id="search" placeholder="Поиск контракта…" aria-label="Поиск"><select id="filter" aria-label="Статус"><option value="all">Все статусы</option><option value="verified">Доказано</option><option value="partial">Частично</option><option value="implemented">Реализовано</option><option value="unknown">Не проверено</option></select></div><div id="rows"></div><p class="footer">Источник — <a href="https://github.com/t0fox/r2o/blob/main/docs/functional-parity-matrix.md">functional-parity-matrix.md</a>. Баллы рассчитываются из строк; частичные контракты дают 0. Зелёный CI не гарантирует полевой паритет на физическом роутере.</p></main><script>const d=${JSON.stringify(d).replace(/</g,"\\u003c")};const byId=new Map(d.items.map(x=>[x.id,x]));const names={verified:"Доказано",partial:"Частично",implemented:"Реализовано",unknown:"Не проверено"};function show(c){const box=document.getElementById("detail");box.replaceChildren();const h=document.createElement("h2");h.textContent=c.name;const p=document.createElement("p");p.textContent=c.statusLabel+" · "+c.points+"/"+c.weight+" баллов";const t=document.createElement("div");t.textContent=c.evidence;box.append(h,p,t);box.scrollIntoView({behavior:"smooth",block:"nearest"})}document.querySelectorAll(".tile").forEach(el=>el.onclick=()=>show(byId.get(+el.dataset.id)));function update(){const host=document.getElementById("rows");host.replaceChildren();const q=document.getElementById("search").value.toLowerCase(),f=document.getElementById("filter").value;for(const c of d.items){if(f!=="all"&&c.status!==f)continue;if(!(c.name+" "+c.group+" "+c.mapping).toLowerCase().includes(q))continue;const line=document.createElement("div");line.className="row";const dot=document.createElement("span");dot.className="dot "+c.status;const mid=document.createElement("div");mid.className="row-content";const name=document.createElement("strong");name.textContent=c.name;const sub=document.createElement("small");sub.textContent=c.group+" · "+names[c.status];mid.append(name,sub);const score=document.createElement("span");score.className="end";score.textContent=c.points+"/"+c.weight;line.append(dot,mid,score);line.onclick=()=>show(c);host.append(line)}}document.getElementById("search").oninput=update;document.getElementById("filter").onchange=update;update();</script></body></html>\n`;
}

function historyPage(entries){
 const pol=entries.map((e,i)=>`${(58+(entries.length===1?.5:i/(entries.length-1))*940).toFixed(1)},${(257-e.percent*2.15).toFixed(1)}`).join(" ");
 const table=entries.slice().reverse().map(e=>`<tr><td>${esc(e.date)}</td><td>${e.points}/${e.weight}</td><td>${e.percent.toFixed(2)}%</td><td><code>${esc(e.sha.slice(0,9))}</code></td></tr>`).join("");
 return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>R2O · История</title><style>body{background:#0c121e;color:#e8f1fa;font:15px Inter,system-ui,sans-serif;max-width:1110px;padding:25px;margin:auto}a{color:#59dfa4}p{color:#a7bad0;line-height:1.6}svg{width:100%;height:auto;border:1px solid #304057;border-radius:13px;background:#172438}table{border-collapse:collapse;width:100%}td,th{padding:12px;text-align:left;border-bottom:1px solid #2c394c}</style></head><body><a href="index.html">← Карта</a><h1>История прогресса R2O</h1><p>Последний коммит с изменением матрицы за каждый день UTC. Исторические проценты могут иметь разные знаменатели: набор требований со временем меняется.</p><svg viewBox="0 0 1050 300"><line x1="58" y1="257" x2="998" y2="257" stroke="#59667b"/><polyline points="${pol}" fill="none" stroke="#36c989" stroke-width="3"/>${entries.map((e,i)=>`<circle cx="${(58+(entries.length===1?.5:i/(entries.length-1))*940).toFixed(1)}" cy="${(257-e.percent*2.15).toFixed(1)}" r="5" fill="#36c989"><title>${esc(e.date)}: ${e.percent.toFixed(2)}%</title></circle>`).join("")}</svg><h2>Даты и баллы</h2><table><thead><tr><th>Дата</th><th>Баллы</th><th>Процент</th><th>Коммит</th></tr></thead><tbody>${table}</tbody></table></body></html>\n`;
}
const root=fileURLToPath(new URL("../",import.meta.url));
const dest=resolve(root,"docs/progress");
const snap=parse(readFileSync(resolve(root,"docs/functional-parity-matrix.md"),"utf8"));
const outputs={
 "progress.json":JSON.stringify(snap,null,2)+"\n",
 "progress.svg":svg(snap),
 "badge-parity.svg":badge(snap,"score"),
 "badge-contracts.svg":badge(snap,"contracts"),
 "index.html":html(snap)
};
const check=process.argv.includes("--check"),pages=process.argv.includes("--pages");
if(!check)mkdirSync(dest,{recursive:true});
let bad=false;
for(const [name,value] of Object.entries(outputs)){
 const path=resolve(dest,name);
 if(check){if(!existsSync(path)||readFileSync(path,"utf8")!==value){console.error("Stale or missing generated progress file:",name);bad=true;}}
 else writeFileSync(path,value);
}
if(bad)process.exit(1);
if(pages){
 const points=[],seen=new Set();
 try{
  const log=execFileSync("git",["log","--first-parent","--format=%H|%cs","--","docs/functional-parity-matrix.md"],{cwd:root,encoding:"utf8",maxBuffer:8*1024*1024});
  for(const line of log.trim().split(/\r?\n/)){
   const [sha,date]=line.split("|");if(!sha||!date||seen.has(date))continue;
   try{const old=parse(execFileSync("git",["show",sha+":docs/functional-parity-matrix.md"],{cwd:root,encoding:"utf8",maxBuffer:8*1024*1024}));seen.add(date);points.push({sha,date,points:old.points,weight:old.weight,percent:old.percent});}catch(e){console.warn("Historical matrix unavailable:",sha.slice(0,9));}
  }
 }catch(e){console.warn("Git history unavailable:",e.message);}
 points.reverse();if(!points.length)points.push({sha:"working-tree",date:snap.date,points:snap.points,weight:snap.weight,percent:snap.percent});
 writeFileSync(resolve(dest,"history.json"),JSON.stringify(points,null,2)+"\n");
 writeFileSync(resolve(dest,"history.html"),historyPage(points));
}
console.log("Verified parity:",snap.points+"/"+snap.weight,"("+snap.percent+"%)");
