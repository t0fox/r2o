const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('playwright');
const url='http://127.0.0.1:'+(process.env.R2O_PREVIEW_PORT||4186);
const dir=path.join(__dirname,'captures/motion');
const tabs=['now','families','boxes','telegram','updates','diagnostics'];
const errors=[];
async function ready(p,route){
  p.on('pageerror',e=>errors.push(e.message));
  p.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
  p.on('request',r=>{if(!r.url().startsWith(url+'/')||r.url().includes('/api/'))errors.push('Сетевой запрос '+r.url());});
  await p.goto(url+'/'+route);
  await p.waitForFunction(()=>document.querySelector('#now-title')?.textContent.includes('Поиск'));
  await p.evaluate(()=>document.fonts.ready);
  await p.waitForTimeout(800);
}
async function tab(p,id){
  await p.locator('[data-nav="'+id+'"]').click();
  await p.locator('#'+id).waitFor({state:'visible'});
  await p.waitForTimeout(540);
}
async function record(page,file){
 const {spawn}=require('node:child_process');
 const encoder=spawn(process.env.FFMPEG_BIN||'ffmpeg',['-hide_banner','-loglevel','error','-y','-f','image2pipe','-r','25','-c:v','mjpeg','-i','pipe:0','-an','-c:v','libvpx-vp9','-pix_fmt','yuv420p','-b:v','1400k','-deadline','realtime','-cpu-used','6',file],{windowsHide:true,stdio:['pipe','ignore','inherit']});
 const done=new Promise((resolve,reject)=>{encoder.on('error',reject);encoder.on('exit',code=>code===0?resolve():reject(Error('FFmpeg '+code)));});
 const cdp=await page.context().newCDPSession(page);
 let latest;
 cdp.on('Page.screencastFrame',frame=>{latest=Buffer.from(frame.data,'base64');cdp.send('Page.screencastFrameAck',{sessionId:frame.sessionId}).catch(()=>{});});
 await cdp.send('Page.startScreencast',{format:'jpeg',quality:90,maxWidth:1280,maxHeight:800});
 const interval=setInterval(()=>{if(latest&&!encoder.stdin.destroyed)encoder.stdin.write(latest);},40);
 return async()=>{clearInterval(interval);await cdp.send('Page.stopScreencast');await cdp.detach();encoder.stdin.end();await done;};
}
async function run(){
 await fs.mkdir(dir,{recursive:true});
 const browser=await chromium.launch({executablePath:process.env.CHROME_BIN||undefined});
 try{
  if(!process.argv.includes('--video-only'))for(const width of [1440,390,320]){
   const context=await browser.newContext({viewport:{width,height:width===1440?960:844}});
   const [p,base]=await Promise.all([context.newPage(),context.newPage()]);
   await Promise.all([ready(p,''),ready(base,'original.html')]);
   for(const id of tabs){
    await Promise.all([tab(p,id),tab(base,id)]);
    const geometry=page=>page.locator('#'+id).evaluate(el=>({
      title:document.title,headings:[...el.querySelectorAll('h1,h2,h3,summary')].map(n=>n.textContent),
      viewport:document.documentElement.clientWidth,scrollWidth:document.documentElement.scrollWidth,
      sections:[...el.children].map(n=>{const r=n.getBoundingClientRect();return [r.x,r.y,r.width,r.height].map(Math.round);})
    }));
    const stable=async page=>{
      await page.bringToFront();
      await page.waitForFunction(id=>{const section=document.getElementById(id);return !gsap.isTweening([section,...section.children]);},id);
      return geometry(page);
    };
    const current=await stable(p), original=await stable(base);
    assert.deepEqual(current,original,width+' / '+id);
    assert.ok(current.scrollWidth<=width,'Переполнение '+width+' / '+id);
    if(width!==320)await p.screenshot({path:path.join(dir,id+'-'+width+'.png')});
    if(id==='now' && width===1440){
      const mask={style:'.lamp::after{visibility:hidden!important}'};
      assert.equal(await p.locator('#status-lamp').evaluate(el=>getComputedStyle(el,'::after').animationName),'signal-breathe');
      const [a,b]=await Promise.all([p.screenshot(mask),base.screenshot(mask)]);
      assert.ok(a.equals(b),'Пиксели исходного обзора и обзора после перехода отличаются');
    }
   }
   await p.bringToFront();
   await tab(p,'families');
   const card=p.locator('.family-card').first(), sum=card.locator(':scope > summary');
   await sum.click();await p.waitForTimeout(440);
   await p.waitForFunction(()=>{const el=document.querySelector('.family-card');return el.open&&!el.style.height;},null,{timeout:2000});
   await sum.evaluate(el=>{el.click();el.click();});await p.waitForTimeout(440);
   assert.ok(await card.evaluate(el=>el.open&&!el.style.height&&!el.hasAttribute('data-open-motion')));
   await sum.click();await p.waitForTimeout(440);assert.equal(await card.evaluate(el=>el.open),false);
   await p.evaluate(()=>['boxes','families','updates','diagnostics'].forEach(id=>document.querySelector('[data-nav="'+id+'"]').click()));
   await p.waitForTimeout(480);assert.equal(await p.locator('[data-nav][aria-current=page]').getAttribute('data-nav'),'diagnostics');
   assert.equal(await p.locator('[data-nav-motion]').count(),0);
   await p.emulateMedia({reducedMotion:'reduce'});assert.equal(await p.locator('#status-lamp').evaluate(el=>getComputedStyle(el,'::after').animationName),'none');await tab(p,'boxes');
   await p.locator('.box-card summary').first().click();assert.equal(await p.locator('[data-open-motion]').count(),0);
   await context.close();
   console.log(width+' px: 6 разделов, геометрия эталона, быстрое переключение, раскрытие и reduced motion — OK');
  }
  if(process.argv.includes('--screens-only')){assert.deepEqual(errors,[]);return;}
  const ctx=await browser.newContext({viewport:{width:1280,height:800}});
  const p=await ctx.newPage();
  await ready(p,'?episode=1');
  await p.locator('#workload-title').evaluate(el=>el.scrollIntoView({block:'center'}));
  const stop=await record(p,path.join(dir,'r2o-motion.webm'));
  try{
  const card=p.locator('#searches .search').first();
  await card.waitFor({state:'visible',timeout:12000});
  await p.waitForTimeout(450);
  await card.evaluate(el=>el.dataset.previewTest='same-card');
  await p.waitForFunction(()=>Number(document.querySelector('#searches .search')?.dataset.stage)>=2);
  assert.equal(await card.getAttribute('data-preview-test'),'same-card');
  await p.screenshot({path:path.join(dir,'episode.png')});
  await p.waitForTimeout(520);
  await card.screenshot({path:path.join(dir,'active-search.png')});
  await p.waitForFunction(()=>document.querySelector('#searches .search')?.dataset.done==='true',{},{timeout:22000});
  await p.waitForFunction(()=>document.querySelector('#searches .quiet')&&!document.querySelector('#searches .search'),{},{timeout:12000});
  await p.waitForTimeout(420);
  }finally{await stop();await ctx.close();}
  const mobile=await browser.newPage({viewport:{width:390,height:844},reducedMotion:'reduce'});
  await ready(mobile,'?episode=1');const live=mobile.locator('#searches .search').first();await live.waitFor({timeout:12000});
  await live.evaluate(el=>el.scrollIntoView({block:'center',behavior:'instant'}));
  await mobile.waitForFunction(()=>Number(document.querySelector('#searches .search')?.dataset.stage)>=2);
  assert.ok(await live.evaluate(el=>el.getBoundingClientRect().bottom<document.querySelector('.index').getBoundingClientRect().top));
  await live.screenshot({path:path.join(dir,'active-search-mobile.png')});
  assert.equal(await live.evaluate(el=>getComputedStyle(el.querySelector('.search-phase'),'::before').animationName),'none');await mobile.close();
  assert.deepEqual(errors,[]);console.log('Запись переходов и событий поиска сохранена. Ошибок JS и запросов к API нет.');
 } finally {await browser.close();}
}
run().catch(e=>{console.error(e);process.exitCode=1;});
