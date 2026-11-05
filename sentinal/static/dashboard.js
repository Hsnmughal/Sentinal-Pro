async function apiFetch(url,options={}){
 const controller=new AbortController();let timer;
 const cancel=()=>controller.abort();
 if(options.signal?.aborted)cancel();else options.signal?.addEventListener('abort',cancel,{once:true});
 const deadline=new Promise((resolve,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new Error('Request timed out; try again'))},15000)});
 try{return await Promise.race([(async()=>{const response=await fetch(url,{...options,signal:controller.signal});const data=await response.json();return {ok:response.ok,status:response.status,json:async()=>data}})(),deadline])}
 catch(error){if(error.name==='AbortError')throw new Error('Request canceled; try again');throw error}
 finally{clearTimeout(timer);options.signal?.removeEventListener('abort',cancel)}
}
function escapeHtml(x){const d=document.createElement('div');d.textContent=x;return d.innerHTML.replaceAll('"','&quot;').replaceAll("'",'&#39;')}
function money(n){const v=Number(n)||0;if(v>=1000000){const m=v/1000000;return '$'+(m%1?m.toFixed(1):m)+'M'}if(v>=1000)return '$'+Math.round(v/1000)+'K';return '$'+Math.round(v)}
function ago(iso){if(!iso)return'';const d=new Date(iso);if(isNaN(d))return String(iso);const s=Date.now()-d.getTime();const h=Math.floor(s/3600000);if(h<1)return'now';if(h<24)return h+'h';const days=Math.floor(s/86400000);if(days<7)return days+'d';return d.toLocaleDateString(undefined,{month:'short',day:'numeric'})}

let lastProgramRevision=window.QUEUE_REVISION||0;
function message(text,error=false){const el=document.getElementById('action-status');if(el){el.textContent=text;el.classList.toggle('bad',error)}}

function updateStats(stats){if(!stats)return;document.querySelectorAll('[data-stat]').forEach(el=>{const key=el.dataset.stat;if(key==='active')el.querySelector('span').textContent='Active programs';const value=window.CHANGE_STATS&&['code','program'].includes(key)?window.CHANGE_STATS[key]:key==='active'?(stats.programs_by_lifecycle||{}).active:key.startsWith('catalog:')?(stats.catalog_by_platform||{})[key.slice(8)]:stats[key];el.querySelector('strong').textContent=['code','program'].includes(key)&&!window.CHANGE_STATS?'—':value||0});
}
function entryHtml(entry){if(typeof entry==='string')return escapeHtml(entry);if(!entry)return'None';const title=entry.label||entry.wording||entry.description||entry.identity||'Entry';const meta=[entry.category,entry.severity].filter(Boolean).map(x=>String(x).replace(/_/g,' ')).join(' / ');const url=typeof entry.url==='string'&&/^https?:\/\//i.test(entry.url)?'<br><a href="'+escapeHtml(entry.url)+'" target="_blank" rel="noopener noreferrer">'+escapeHtml(entry.url)+'</a>':'';return'<b>'+escapeHtml(title)+'</b>'+(meta?' <span class="muted">'+escapeHtml(meta)+'</span>':'')+url}
function valueHtml(value){if(Array.isArray(value))return value.length?'<ul>'+value.map(x=>'<li>'+entryHtml(x)+'</li>').join('')+'</ul>':'<p class="muted">None</p>';if(value&&typeof value==='object'&&(value.label||value.wording))return'<p>'+entryHtml(value)+'</p>';return'<pre>'+escapeHtml(JSON.stringify(value,null,2))+'</pre>'}
function changedFilesHtml(meta,eventId){meta=meta||{};const files=meta.changed_files||[];const uri=meta.compare_url||meta.url;const link=typeof uri==='string'&&/^https?:\/\//i.test(uri)?'<p><a href="'+escapeHtml(uri)+'" target="_blank" rel="noopener noreferrer">View source comparison</a></p>':'';
return files.map((file,index)=>'<details class="file-diff" data-view-key="file:'+escapeHtml((file.path||file.filename||'Unknown file')+(file.patch_scope==='commit'?':'+commitBoundaryLabel(file,'before')+'...'+commitBoundaryLabel(file,'after'):'')).replaceAll('"','&quot;')+'"><summary><span class="fd-path">'+escapeHtml(file.path||file.filename||'Unknown file')+'</span><span class="fd-meta"> · '+escapeHtml(file.status||'changed')+'</span><span class="fd-meta"> · <span class="fd-adds">+'+Number(file.additions||0)+'</span> / <span class="fd-dels">−'+Number(file.deletions||0)+'</span></span></summary>'+(file.previous_path?'<p class="muted">Renamed from '+escapeHtml(file.previous_path)+'</p>':'')+(file.patch_scope==='legacy_unverified'?'<p class="bad">Historical patch coverage is unverified. Check the source comparison before relying on these revisions.</p>':'')+(file.patch_scope==='commit'?'<p class="muted">Individual commit patch: <code>'+escapeHtml(commitBoundaryLabel(file,'before'))+'</code> → <code>'+escapeHtml(commitBoundaryLabel(file,'after'))+'</code></p>':'')+(file.patch_unavailable_reason?'<p class="muted">'+escapeHtml(file.patch_unavailable_reason)+'</p>':'')+(file.patch_truncated?'<p class="bad">This recorded patch is truncated. Check the source comparison for the complete diff.</p>':'')+(file.patch?'<pre class="diff-code">'+escapeHtml(file.patch)+'</pre>':file.patch_recorded?'<pre class="diff-code" data-patch-url="/api/events/'+Number(eventId)+'/files/'+index+'/patch">Expand to load recorded patch…</pre>':'<p class="muted">No text patch recorded for this file. It may be binary or unavailable from the source.</p>')+'</details>').join('')+link}

function commitBoundaryLabel(file,side){const value=side==='before'?file.patch_before:file.patch_after;if(value)return String(value);const recordedPatch=file.patch_recorded||(typeof file.patch==='string'&&file.patch.trim());return side==='before'&&recordedPatch&&!file.patch_unavailable_reason?'empty tree':'unknown'}

function hasFileDiffs(e){return (e.metadata?.changed_files||[]).some(file=>file.patch_recorded||(typeof file.patch==='string'&&file.patch.trim()))}

function changeBodyHtml(e){const meta=e.metadata||{},code=e.change_type==='code';return (meta.patch_range_unavailable?'<p class="muted">'+escapeHtml(meta.patch_unavailable_reason||'A file comparison is unavailable for this release boundary.')+'</p>':'')+(meta.truncated||meta.history_rewritten?'<p class="bad">Recorded comparison is incomplete. Check the source comparison for full coverage.</p>':'')+'<h4>'+(e.kind==='PROXY_IMPLEMENTATION_CHANGED'?'Previous implementation':code?'Previous revision':'Before')+'</h4>'+valueHtml(e.before)+'<h4>'+(e.kind==='PROXY_IMPLEMENTATION_CHANGED'?'Current implementation':code?'New revision':'After')+'</h4>'+valueHtml(e.after)+(code?changedFilesHtml(meta,e.id)+(hasFileDiffs(e)?'<p><a href="/api/events/'+Number(e.id)+'/diffs">Download file diffs (.zip)</a></p>':'<p class="muted">No file patches recorded for this change.</p>'):'')}

// Patch text is fetched only when a user expands a particular file. The
// document-level capture listener also covers dynamically replaced dossiers.
async function loadExpandedPatch(details){
 const pre=details.querySelector('.diff-code[data-patch-url]');
 if(!pre||pre.dataset.loading==='true')return;
 pre.dataset.loading='true';pre.textContent='Loading recorded patch…';
 try{
  const response=await apiFetch(pre.dataset.patchUrl);
  const data=await response.json();
  if(!response.ok)throw Error(data.error||'Patch unavailable');
  if(typeof data.patch!=='string')throw Error('Invalid patch response');
  pre.textContent=data.patch;pre.removeAttribute('data-patch-url');delete pre.dataset.patchState;
 }catch(error){pre.textContent='Unable to load patch. Close and reopen to retry.';pre.dataset.patchState='error'}
 finally{delete pre.dataset.loading}
}
if(typeof document!=='undefined'&&document.addEventListener){
 document.addEventListener('toggle',event=>{
  const details=event.target;
  if(details?.classList?.contains('file-diff')&&details.open)loadExpandedPatch(details);
 },true);
}

async function runAction(action,button){button.disabled=true;const old=button.textContent;button.textContent='Queued…';try{const r=await apiFetch('/api/actions/'+action,{method:'POST'});const j=await r.json();if(!r.ok)throw new Error(j.error||'Request failed');button.textContent=j.queued?'Queued '+j.queued:'No configured checks';message(j.queued?'Checks queued; request limits still apply':'No configured checks for this source');setTimeout(loadStatus,500)}catch(e){message(e.message,true);button.textContent=old}finally{setTimeout(()=>{button.disabled=false;button.textContent=old},1500)}}

async function retryJob(jobKey,button){button.disabled=true;try{const r=await apiFetch('/api/actions/retry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_key:jobKey})});const j=await r.json();if(!r.ok)throw new Error(j.error||'Request failed');button.textContent='Queued';setTimeout(loadStatus,500)}catch(e){message(e.message,true);button.disabled=false}}

function renderSweep(sweep){const el=document.getElementById('sweep');if(!el||!sweep)return;
const drawer=document.getElementById('failures'),open=!!(drawer&&drawer.classList&&drawer.classList.contains('open'));
const html='Scheduled checks <b>'+sweep.total+'</b> · successful <b>'+sweep.successful+'</b> · failed <b class="'+(sweep.failed?'bad':'')+'">'+sweep.failed+'</b> · waiting <b>'+sweep.pending+'</b> · running <b>'+(sweep.running||0)+'</b> · deferred <b>'+(sweep.deferred||0)+'</b> · stale <b class="'+(sweep.stale?'stale':'')+'">'+sweep.stale+'</b>'
+((sweep.failed||sweep.deferred)?' <button class="link" aria-controls="failures" aria-expanded="'+open+'" onclick="toggleDrawer()">'+(open?'hide check details':'show check details')+'</button>':'');
if(el.__html!==html){el.innerHTML=html;el.__html=html}}

function friendlyError(error){if(!error)return'Previous check failed; retry pending';if(/getaddrinfo|DNS|name resolution/i.test(error))return'DNS lookup failed. This source will retry with shared backoff.';if(/timed out|timeout/i.test(error))return'Connection timed out. Other sources continue monitoring.';if(/HTTP 404/i.test(error))return'Source unavailable (404). Check the URL or repository access.';if(/HTTP 401/i.test(error))return'Source rejected credentials (401).';if(/HTTP 429|rate limit/i.test(error))return'Source rate-limited. Requests wait for cooldown.';return error.length>220?error.slice(0,220)+'...':error}

let failuresRenderKey=null,failuresRendered='';
// The summary payload lists only actionable error/blocked rows; deferred checks
// arrive as waiting counts. A signature skips rebuilds when nothing changed, so
// opening/keeping the drawer never repaints identical rows.
function renderFailures(failed,{deferredTotal=0,failedTotal=0,canRetry=true}={}){const box=document.getElementById('failures');if(!box)return;
const all=failed||[];const errors=all.filter(j=>j.last_status!=='deferred');
if(!deferredTotal)deferredTotal=all.filter(j=>j.last_status==='deferred').length;
if(!failedTotal)failedTotal=all.length;
const key=JSON.stringify([canRetry,deferredTotal,failedTotal,errors.map(j=>[j.job_key,j.last_status,j.last_error,j.next_run_at,j.retry_at,j.manually_queued?1:0])]);
if(key===failuresRenderKey)return;failuresRenderKey=key;
if(!errors.length&&!deferredTotal){box.classList.remove('open');if(failuresRendered){box.innerHTML='';failuresRendered=''}return}
const opened=new Set(Array.from(box.querySelectorAll('.failure')).filter(row=>row.querySelector('details')?.open).map(row=>row.dataset.jobKey));
const rows=(jobs,waiting)=>jobs.map(j=>
'<div class="failure" data-job-key="'+escapeHtml(j.job_key)+'"><b>'+escapeHtml(j.job_key)+'</b><span class="err">'+escapeHtml(waiting?waitingReason(j.last_error):friendlyError(j.last_error))+'</span>'
+(j.last_error?'<details><summary>Technical details</summary><pre>'+escapeHtml(j.last_error)+'</pre></details>':'')+'<span class="retry">'+escapeHtml(j.last_status==='blocked'?'Monitoring stopped; retry to recheck this source':new Date(j.retry_at||j.next_run_at).getTime()<=Date.now()?'Queued; awaiting scheduler capacity':'Next attempt '+new Date(j.retry_at||j.next_run_at).toLocaleString())+'</span>'
+(canRetry&&!waiting?'<button '+(j.manually_queued?'disabled ':'')+'data-job-key="'+escapeHtml(j.job_key)+'" onclick="retryJob(this.dataset.jobKey,this)">'+(j.manually_queued?'Queued':'Retry now')+'</button>':'')+'</div>').join('');
const extra=failedTotal-errors.length-deferredTotal;
const html=(errors.length?'<h3>FAILED TARGETS</h3>'+rows(errors,false):'')
+(deferredTotal?'<h3>WAITING CHECKS</h3><div class="failure"><b>'+deferredTotal+' check'+(deferredTotal===1?'':'s')+'</b><span class="retry">Queued; awaiting scheduler capacity. Deferred checks retry automatically once request limits or cooldowns clear.</span></div>':'')
+(extra>0?'<div class="failure"><span class="retry">'+extra+' further check'+(extra===1?'':'s')+' finished with warnings and recovered on their own; the full list is in the detailed status.</span></div>':'');
box.innerHTML=html;failuresRendered=html;
box.querySelectorAll('.failure').forEach(row=>{const details=row.querySelector('details');if(details&&opened.has(row.dataset.jobKey))details.open=true})}

function waitingReason(error){if(/request budget exhausted|spacing|concurrency/i.test(error||''))return'Waiting for request capacity; automatically queued.';if(/HTTP 429|rate.limit|Retry-After/i.test(error||''))return'Waiting for source cooldown; retries resume gradually.';return'Waiting to retry automatically.'}

function toggleDrawer(){const box=document.getElementById('failures');if(box){const open=box.classList.toggle('open');const button=document.querySelector('#sweep .link');if(button){button.textContent=open?'hide check details':'show check details';button.setAttribute('aria-expanded',String(open))}}}

async function loadStatus(){if(loadStatus.pending)return;loadStatus.pending=true;try{const r=await apiFetch('/api/status');const s=await r.json();if(!r.ok)throw new Error(s.error||'Unable to load monitoring status');
const schedulerState=s.runtime?.scheduler?.value||{};
const schedStatus=document.getElementById('scheduler-status');
const schedText=schedulerState.state==='failed'?'Scheduler stopped after an error: '+schedulerState.error:schedulerState.state==='retrying'?'Storage temporarily unavailable; monitoring retries in '+schedulerState.retry_in_seconds+' seconds':s.running?'Scheduler active · checks due work every '+s.tick_seconds+' seconds':'Scheduler is not running';
if(schedStatus.__text!==schedText){schedStatus.textContent=schedText;schedStatus.__text=schedText}
const health=document.getElementById('health'),failed=s.sweep?.failed||0;
const healthHtml='<i></i> '+(schedulerState.state==='failed'?'MONITOR STOPPED':schedulerState.state==='retrying'?'MONITOR RETRYING':s.running?(failed?'MONITORING · '+failed+' SOURCE FAILURES':'MONITORING LOCALLY'):'MANUAL MODE');
if(health.__html!==healthHtml){health.innerHTML=healthHtml;health.__html=healthHtml}
health.classList.toggle('warn',(s.running&&failed>0)||['failed','retrying'].includes(schedulerState.state));health.classList.toggle('idle',!s.running);
const due=s.runtime.last_scheduler_pass?.value;
const revision=s.runtime.queue_revision?.value||0;
if(lastProgramRevision!==revision&&typeof researchLoad==='function'){
 if(await researchLoad())lastProgramRevision=revision;
}
const detail=document.getElementById('scheduler-detail');
const detailText=due?(due.running?'Current batch: ':'Last batch: ')+new Date(due.checked_at).toLocaleString()+' · '+due.completed+'/'+(due.total||due.completed+due.failed+due.deferred)+' completed · '+due.failed+' failed'+(due.deferred?' · '+due.deferred+' deferred (cooldown)':''):'';
if(detail.__text!==detailText){detail.textContent=detailText;detail.__text=detailText}
renderSweep(s.sweep);renderFailures(s.failed||[],{deferredTotal:s.deferred_total,failedTotal:s.failed_total,canRetry:s.running})}catch(e){
const schedStatus=document.getElementById('scheduler-status');const schedText='Unable to load scheduler status; retrying automatically';if(schedStatus.__text!==schedText){schedStatus.textContent=schedText;schedStatus.__text=schedText}
const health=document.getElementById('health');health.textContent='MONITOR STATUS UNAVAILABLE';health.__html=null;health.classList.add('warn');health.classList.remove('idle')}finally{loadStatus.pending=false}}

loadStatus();setInterval(()=>{if(!document.hidden)loadStatus()},15000);

function applyTheme(mode,{animate=true}={}){
 const next=mode==='light'?'light':'dark';
 const root=document.documentElement;
 const swap=()=>{
  root?.setAttribute?.('data-theme',next);
  document.querySelector?.('meta[name="theme-color"]')?.setAttribute('content',next==='light'?'#f4f4f3':'#0a0a0a');
  document.querySelectorAll?.('[data-set-theme]').forEach(btn=>{
   btn.setAttribute('aria-pressed',String(btn.dataset.setTheme===next));
  });
  try{localStorage.setItem('sentinal-theme',next)}catch(e){}
 };
 // Crossfade priority chain, all four evergreen engines:
 //  1. View transition (Chromium: Chrome/Brave/Edge; Safari 18+; Firefox 141+)
 //     — one composited snapshot, no per-element color interpolation.
 //  2. Fallback coordinated fade (older Firefox/Safari) — colors-only, short.
 //  3. Instant swap — first paint and prefers-reduced-motion.
 const reduced=window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches;
 if(animate&&root?.getAttribute?.('data-theme')!==next&&!reduced){
  if(typeof document.startViewTransition==='function'){
   document.startViewTransition(swap);return;
  }
  root?.classList?.add?.('theme-switching');
  swap();
  setTimeout(()=>root?.classList?.remove?.('theme-switching'),200);
 }else{swap()}
}
function initTheme(){
 let saved='dark';
 try{saved=localStorage.getItem('sentinal-theme')||(window.matchMedia?.('(prefers-color-scheme: light)').matches?'light':'dark')}catch(e){}
 applyTheme(saved,{animate:false});
 document.querySelectorAll?.('[data-set-theme]').forEach(btn=>{
  btn.addEventListener('click',()=>applyTheme(btn.dataset.setTheme));
 });
}
if(typeof document!=='undefined'&&document.querySelectorAll)initTheme();

// One interaction at a time: an open "Refresh sources" popover closes as soon
// as the pointer or focus moves to any control outside it. The capture-phase
// click listener fires before native pickers (e.g. selects) open their popup,
// so two interacting controls are never open at once.
if(typeof document!=='undefined'&&document.addEventListener){
 const closePopoversOutside=target=>{
  document.querySelectorAll('details.manual-checks[open]').forEach(d=>{
   if(!d.contains(target))d.open=false;
  });
 };
 document.addEventListener('click',e=>closePopoversOutside(e.target),true);
 document.addEventListener('focusin',e=>closePopoversOutside(e.target));
}
