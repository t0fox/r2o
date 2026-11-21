/* Все ответы принадлежат вкладке. Оригинальные обработчики панели работают с демо-снимком. */
(() => {
  'use strict';
  const params=new URLSearchParams(location.search);
  let episodeStart;
  const phases=['заводим поиск','ждём форму приветствия','распознаём поведение','спрашиваем коробку о свойствах','выводим планы','проверяем выведенный план','подтверждено, смотрим живой трафик'];
  const names=['googlevideo.com','discord.media','whatsapp.net'];
  const groups=names.map((suffix,i)=>({suffix,active:true,transport:6,shape:1,family:4,plan_id:'p-'+(i+1),
    evidence:['edge-a.'+suffix,'edge-b.'+suffix],evidence_count:2,exceptions:[]}));
  const boxes=groups.map((g,i)=>({id:'box-0'+(i+1),created:1795000000,updated:1795100000,
    signatures:[{kind:'timeout',human:'Ответ не получен до истечения таймаута',seen:i+1}],
    bindings:g.evidence.map(target=>({target,kind:'name',transport:6,shape:1,family:4,enabled:true,plan_id:g.plan_id})),
    plans:[{id:g.plan_id,proto:'tcp',human:'Подтверждённый план',enabled:true,successes:i+1,text:'Демонстрационный план '+g.plan_id}]}));
  let engine=true, proxy=true, recording=true, workers=['worker.example.invalid'], clear=false;
  const update={current:'533d9c31',never:true,auto_enabled:false};
  const samples=Array.from({length:24},(_,i)=>({at:1795305600+i*60,processes:{controller:{pid:1581,rss_kib:13800+i*14}}}));
  const report=()=>({enabled:recording,samples,events:[],sample_interval_ms:60000,anomalies:[]});
  const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});
  function snapshot(){
    if(episodeStart===undefined)episodeStart=Date.now()+5500;
    const elapsed=Date.now()-episodeStart;
    const cycle=elapsed<0?elapsed:elapsed%23500;
    const step=Math.floor(cycle/2200);
    const active=engine && params.has('episode') && step>=0 && step<phases.length;
    return {snapshot:{engine_running:engine,live_fresh:true,mode:'apply',controls_enabled:true,
      panel_listen:'Демо · 127.0.0.1',version:'533d9c31',build_id:'533d9c31',catalog_available:true,
      telegram_status:proxy?'local':'stopped',telegram_configured:true,telegram_port:1443,
      telegram_stats:{listener_ready:proxy,active_connections:0,active_sessions:[]},stages:[
        {name:'Контроллер',built:true},{name:'Datapath',built:true},{name:'Панель',built:true}]},
      knowledge:{linked:engine,groups:clear?[]:groups,boxes:clear?[]:boxes,confirms:0,probes_used:active?step:0,
        measurements:{active:active?1:0,limit:2,queued:0,free_pct:95,cores:2},searches:active?[{
          target:'edge-a.googlevideo.com',ip:'192.0.2.42',family:4,transport:6,port:443,shape:1,
          phase:phases[step],plan_id:step>=5?'p-1':'',since:new Date(Date.now()-cycle).toISOString(),attempts:step>=4?1:0,probes:step>=5?1:0,candidate:step>=5?'p-1':''}]:[]}};
  }
  window.fetch=async (input,init={})=>{
    const u=new URL(typeof input==='string'?input:input.url,location.origin);
    if(u.origin!==location.origin)return reply({},404);
    switch(u.pathname){
      case '/api/status':return reply(snapshot());
      case '/api/update':return reply(update);
      case '/api/diagnostics':
        if(u.search==='?disable')recording=false;
        if(u.search==='?enable')recording=true;
        return reply(report());
      case '/api/telegram/workers':
        if(init.method==='POST')workers=JSON.parse(init.body).domains;
        return reply({domains:workers});
    }
    if(init.method!=='POST')return reply({},404);
    switch(u.pathname){
      case '/api/control/stop':engine=false;break;
      case '/api/control/start':case '/api/control/restart':engine=true;break;
      case '/api/control/clear-found':clear=true;break;
      case '/api/control/telegram-enable':proxy=true;break;
      case '/api/control/telegram-disable':proxy=false;break;
      case '/api/control/telegram-check':break;
      case '/api/control/update-check':Object.assign(update,{never:false,check_ok:true,checked_utc:1795305600,latest:{version:'demo.2',release_id:'demo.2',notes:'Локальный демонстрационный выпуск'}});break;
      case '/api/control/update-install':update.current='demo.2';break;
      case '/api/control/update-auto-on':update.auto_enabled=true;break;
      case '/api/control/update-auto-off':update.auto_enabled=false;break;
      default:return reply({},404);
    }
    return reply({ok:true});
  };
  document.addEventListener('click',e=>{
    if(!e.target.closest('#diagnostic-download'))return;
    e.preventDefault();
    const a=document.createElement('a'),url=URL.createObjectURL(new Blob([JSON.stringify(report())],{type:'application/json'}));
    a.href=url;a.download='r2o-demo.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),500);
  });
})();
