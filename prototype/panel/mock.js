/* Все ответы принадлежат вкладке. Оригинальные обработчики панели работают с демо-снимком. */
(() => {
  'use strict';
  const params=new URLSearchParams(location.search);
  const showcase=params.get('episode')==='live';
  let episodeStart;
  let shownStage=-1, shownAt=0, firstStageAt=0;
  if(showcase)document.addEventListener('DOMContentLoaded',()=>{
    const card=document.querySelector('.workload-card');
    const replay=document.createElement('button');
    replay.type='button';replay.className='episode-replay';replay.textContent='Демо · Повторить поиск';
    card.querySelector('.card-head').append(replay);
    replay.addEventListener('click',()=>{
      episodeStart=Date.now()+2600;
      shownStage=-1;
      window.dispatchEvent(new Event('r2o-demo-replay'));
    });
    document.fonts.ready.then(()=>requestAnimationFrame(()=>{
      if(card.offsetHeight)card.scrollIntoView({block:'start',behavior:'instant'});
    }));
  });
  const phases=['заводим поиск','ждём форму приветствия','распознаём поведение','спрашиваем коробку о свойствах','выводим планы','проверяем выведенный план','подтверждено, смотрим живой трафик'];
  const names=['googlevideo.com','discord.media','whatsapp.net'];
  const plans=['split sni_middle +0\norder reverse','segment 256\nsplit payload_start +1','split sni_middle +0\npace 15000'];
  const signals=['Медиасегмент не получен до таймаута','Медиасервер закрыл соединение','Приём вложения прерван'];
  const epoch=Date.now(), ago=minutes=>new Date(epoch-minutes*60000).toISOString();
  const groups=names.map((suffix,i)=>({suffix,active:true,transport:6,shape:1,family:4,plan_id:['YT-04','DC-02','WA-03'][i],
    evidence:['edge-a.'+suffix,'edge-b.'+suffix],evidence_count:2,exceptions:['edge-c.'+suffix]}));
  const boxes=groups.map((g,i)=>({id:'box-0'+(i+1),created:ago(240+i*20),updated:ago(12+i*4),
    signals:[{kind:'timeout',human:signals[i],seen:3+i}],
    bindings:[...g.evidence,...g.exceptions].map(target=>({target,kind:'name',transport:6,shape:1,family:4,enabled:true,plan_id:g.plan_id,confirmed:ago(12+i*4),successes:3+i,level:3,level_name:'Данные получены'})),
    plans:[{id:g.plan_id,proto:'tcp',enabled:true,successes:3+i,text:'r2o-plan 1 5\nproto tcp tls\n'+plans[i]}]}));
  boxes[0].plans.push({id:'YT-07',proto:'tls',enabled:true,successes:2,
    text:'r2o-plan 1 5\nproto tcp tls\nsegment 1400\npayload-pad64 2 391 15\nseqovl payload=2 poison=0\norder forward'});
  ['i.ytimg.com','www.youtube.com'].forEach(target=>boxes[0].bindings.push({...boxes[0].bindings[0],target,plan_id:'YT-07',successes:1}));
  let engine=true, proxy=true, recording=true, workers=['worker.example.invalid'], clear=false;
  const now=()=>Math.floor(Date.now()/1000);
  const update={current:'21.11.2026',check_ok:true,auto:true,checked_utc:now()-300,
    latest:{version:'22.11.2026 · preview',release_id:'22.11.2026-preview',notes:'Улучшена читаемость диагностики. Добавлена история этапов установки.'}};
  let installStart=0, checkStart=0, failOnce=params.get('install')==='retry', dcStart=0;
  function updateSnapshot(){
    if(checkStart && Date.now()-checkStart>=1700){
      Object.assign(update,{busy:'',checked_utc:now(),check_ok:true});
      checkStart=0;
    }
    if(installStart){
      update.demo_stage=Math.min(4,Math.floor((Date.now()-installStart)/2600));
      const failed=failOnce && update.demo_stage>=1;
      if(failed || update.demo_stage===4){
        Object.assign(update,{busy:'',last_ok:!failed,last_release:update.latest.release_id,last_utc:now(),
          last_message:failed?'Демо: подпись пакета не прошла проверку. Сохранена прежняя версия.':'Демо: новая версия установлена, службы готовы.'});
        if(!failed)update.current=update.latest.release_id;
        failOnce=false;
        installStart=0;
      }
    }
    return update;
  }
  function telegramDiagnostics(){
    if(!dcStart)return {state:'never'};
    if(Date.now()-dcStart<2500)return {state:'running'};
    return {state:'healthy',checked_at:Math.floor(dcStart/1000)+2,data_centers:[1,2,3,4,5].map(dc=>({dc,state:'healthy',
      routes:[{transport:'direct-wss',state:'healthy',dns_ms:3,tcp_ms:12+dc,tls_ms:21+dc,mtproto_ms:42+dc}]}))};
  }
  const samples=Array.from({length:24},(_,i)=>({at:1795305600+i*60,processes:{controller:{pid:1581,rss_kib:13800+i*14}}}));
  const report=()=>({enabled:recording,samples,events:[],sample_interval_ms:60000,anomalies:[]});
  const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});
  function snapshot(){
    if(episodeStart===undefined)episodeStart=Date.now()+(showcase?2600:5500);
    const elapsed=Date.now()-episodeStart;
    const fixed={plan:11500,applied:14000}[params.get('episode')];
    const cycle=typeof fixed==='number'?fixed:showcase?elapsed:elapsed<0?elapsed:elapsed%23500;
    if(showcase && engine && elapsed>=0 && shownStage<phases.length-1 && (shownStage<0 || Date.now()-shownAt>=1800)){
      shownStage++;
      shownAt=Date.now();
      if(shownStage===0)firstStageAt=shownAt;
    }
    const step=showcase?shownStage:Math.floor(cycle/2200);
    const active=engine && params.has('episode') && step>=0 && step<phases.length;
    const sessions=proxy && params.get('telegram')!=='idle'?[{id:1,dc:2,stage:'first_wss_binary_response',direct_state:'selected',
      direct_transport:'direct_wss',selected_transport:'direct_wss',fallback_state:'idle',telegram_response_seen:true,
      bytes_from_clients:18400,bytes_from_upstreams:76200}]:[];
    return {snapshot:{engine_running:engine,live_fresh:true,mode:'apply',controls_enabled:true,
      panel_listen:'Демо · 127.0.0.1',version:'64cf01b0',build_id:'64cf01b0',catalog_available:true,
      telegram_status:proxy?(sessions.length?'connected':'local'):'stopped',telegram_configured:true,telegram_port:1443,
      telegram_diagnostics:telegramDiagnostics(),telegram_stats:{listener_ready:proxy,active_connections:sessions.length,active_sessions:sessions,
        accepted_connections:19,mtproto_success:18,mtproto_failure:1,last_success_dc:2,last_success_latency_ms:37,bytes_from_clients:18400,bytes_from_upstreams:76200,
        client_response_latency_samples:18,client_response_latency_p50_us:37000,client_response_latency_p95_us:62000},stages:[
        {name:'Контроллер',built:true},{name:'Datapath',built:true},{name:'Панель',built:true}]},
      knowledge:{linked:engine,groups:clear?[]:groups,boxes:clear?[]:boxes,confirms:active && step===6?1:0,probes_used:active?step:0,
        measurements:{active:active && step<6?1:0,limit:2,queued:0,free_pct:95,cores:2},searches:active?[{
          target:'edge-a.googlevideo.com',ip:'192.0.2.42',family:4,transport:6,port:443,shape:1,
          phase:phases[step],plan_id:step>=5?groups[0].plan_id:'',applied_plan_id:step===6?groups[0].plan_id:'',
          completed_at:showcase && step===6?new Date(shownAt).toISOString():null,
          since:new Date(showcase?firstStageAt:(typeof fixed==='number'?epoch:Date.now())-cycle).toISOString(),attempts:step>=4?1:0,probes:step>=5?1:0,candidate:step>=5?groups[0].plan_id:''}]:[]}};
  }
  window.fetch=async (input,init={})=>{
    const u=new URL(typeof input==='string'?input:input.url,location.origin);
    if(u.origin!==location.origin)return reply({},404);
    switch(u.pathname){
      case '/api/status':return reply(snapshot());
      case '/api/update':return reply(updateSnapshot());
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
      case '/api/control/telegram-check':dcStart=Date.now();break;
      case '/api/control/update-check':checkStart=Date.now();update.busy='checking';break;
      case '/api/control/update-install':installStart=Date.now();Object.assign(update,{busy:'installing',demo_stage:0,last_ok:null});break;
      case '/api/control/update-auto-on':update.auto=true;break;
      case '/api/control/update-auto-off':update.auto=false;break;
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
