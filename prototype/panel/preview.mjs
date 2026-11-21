import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const root=fileURLToPath(new URL('.',import.meta.url));
const redesign=process.argv.includes('--redesign');
const dist=join(root,redesign?'dist/redesign':'dist/motion');
const ref='64cf01b018a81f1d6df91e912533ae1defe1c9dc';
const source=ref+':crates/r2o-panel/assets/';
const original=name=>execFileSync('git',['show',source+name],{cwd:root,maxBuffer:4*1024*1024});
const readAsset=name=>redesign?readFile(join(root,'../../crates/r2o-panel/assets',name)):original(name);
const html=(await readAsset('index.html')).toString();
const css=(await readAsset('panel.css')).toString();
const files=new Map();
for(const match of (html+css).matchAll(/(?:href="|src="|url\(")\/assets\/([\w.-]+)/g)){
  const name=match[1];
  if(!files.has('assets/'+name))files.set('assets/'+name,await readAsset((name.endsWith('.woff2')?'fonts/':'')+name));
}
const fixtureTag='<script src="/assets/mock.js" defer></script>';
const page=html.replace('<script src="/assets/gsap.js"',fixtureTag+'\n  <script src="/assets/gsap.js"');
files.set('assets/mock.js',await readFile(join(root,'mock.js')));
if(redesign){
  files.set('index.html',page.replace('<html ','<html data-redesign-preview ')
    .replace('Панель работает локально на роутере и обращается только к его /api.', 'Демонстрационные данные. Действия выполняются только в этой вкладке.')
    .replace('</head>',`<style>
      .mast-host:not(:empty) { display: inline-block; }
      .episode-replay { margin-left: auto; }
    </style></head>`));
} else {
  files.set('index.html',page.replace('</head>','<link rel="stylesheet" href="/assets/motion.css"></head>'));
  files.set('assets/motion.css',await readFile(join(root,'motion.css')));
  files.set('original.html',page.replace('src="/assets/panel.js"','src="/assets/original.js"'));
  files.set('assets/original.js',files.get('assets/panel.js'));
  const scratch=await mkdtemp(join(tmpdir(),'r2o-motion-'));
  try {
    await writeFile(join(scratch,'panel.js'),files.get('assets/panel.js'));
    execFileSync('git',['apply','--no-index',join(root,'motion.patch')],{cwd:scratch});
    execFileSync('git',['apply','--no-index',join(root,'views.patch')],{cwd:scratch});
    files.set('assets/panel.js',await readFile(join(scratch,'panel.js')));
  } finally {await rm(scratch,{recursive:true,force:true});}
}
await mkdir(join(dist,'assets'),{recursive:true});
for(const [name,body] of files)await writeFile(join(dist,name),body);
console.log('Собрано в '+dist);
if(!process.argv.includes('--build')){
  const types={html:'text/html',css:'text/css',js:'text/javascript',svg:'image/svg+xml',woff2:'font/woff2'};
  const port=Number(process.env.R2O_PREVIEW_PORT||(redesign?4187:4186));
  createServer((req,res)=>{
    const name=req.url.split('?')[0].slice(1)||'index.html';
    if(req.method!=='GET'||!files.has(name)){res.writeHead(404).end();return;}
    res.writeHead(200,{'Content-Type':types[basename(name).split('.').pop()],'Cache-Control':'no-store',
      'Content-Security-Policy':"default-src 'self'; connect-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; form-action 'none'"}).end(files.get(name));
  }).listen(port,'127.0.0.1',()=>console.log('http://127.0.0.1:'+port));
}
