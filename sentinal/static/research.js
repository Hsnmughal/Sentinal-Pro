/* One program card; changes remain independently reviewable in its dossier. */

const research={programs:[],selected:null,request:0,loading:false,revision:null,detailRevision:null,loadError:null};

// The master/detail workspace becomes an explicit two-screen flow below 980px.
// Desktop layout still displays both regions simultaneously.
function setMobileView(view){
 const panes=document.querySelector('.panes');
 if(panes)panes.dataset.mobileView=view==='detail'?'detail':'list';
}
function focusPanel(id){
 const panel=document.getElementById(id);if(!panel)return;
 panel.focus?.({preventScroll:true});
 if(window.matchMedia?.('(max-width: 980px)')?.matches)
  panel.scrollIntoView?.({block:'start',behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'});
}

const rEscape=value=>escapeHtml(String(value??''));
const rCount=(value,label)=>value+' '+label+(value===1?'':'s');

// Failed-load card, shared by researchLoad's catch and researchRender's empty
// fallback: filter interactions and Reset must never replace it with the
// "no programs match" dead end while nothing has loaded — Try again is the
// only recovery path until the background poll succeeds.
const retryCardHtml=message=>'<div class="load-state" role="alert"><p>'+rEscape(message)+'</p><button data-retry-programs>Try again</button></div>';
const bindRetryCard=list=>{const btn=list.querySelector('[data-retry-programs]');if(btn)btn.onclick=()=>researchLoad()};

const rUrl=value=>{try{const u=new URL(value);return ['https:','http:'].includes(u.protocol)&&!u.username&&!u.password?u.href:null}catch{return null}};

const rLink=(url,label)=>rUrl(url)?'<a target="_blank" rel="noopener noreferrer" href="'+rEscape(rUrl(url))+'">'+rEscape(label||url)+'</a>':rEscape(label||'Link unavailable');

const rList=items=>items?.length?'<ul>'+items.map(item=>'<li>'+entryHtml(item)+'</li>').join('')+'</ul>':'<p class="muted">No evidence recorded.</p>';

function researchMatches(p,filters){return (!filters.search||p.name.toLowerCase().includes(filters.search))&&(!filters.lifecycle||p.lifecycle===filters.lifecycle)&&(!filters.scoped||p.scoped_change_count>0)&&(!filters.open||p.change_count>0)&&(!filters.category||(filters.category==='code'?p.code_change_count>0:p.program_change_count>0))&&['chain','language','type'].every(key=>!filters[key]||(filters[key]==='__unknown'?!p.fit[{chain:'chains',language:'languages',type:'protocol_types'}[key]].length:(p.fit[{chain:'chains',language:'languages',type:'protocol_types'}[key]]||[]).includes(filters[key])))}

function researchRender(){const list=document.getElementById('program-list'),scroll=list.scrollTop,focused=document.activeElement?.closest?.('[data-program]')?.dataset.program;const filters={search:document.getElementById('program-search').value.trim().toLowerCase(),lifecycle:document.getElementById('filter-lifecycle').value,scoped:document.getElementById('filter-scoped').checked,open:document.getElementById('filter-open').checked,category:document.getElementById('filter-investigation').value};for(const key of ['chain','language','type'])filters[key]=document.getElementById('filter-'+key).value;

const rows=research.programs.filter(p=>researchMatches(p,filters));const sort=document.getElementById('program-sort').value;

rows.sort(sort==='reward'?(a,b)=>(b.max_bounty||0)-(a.max_bounty||0):sort==='recent'?(a,b)=>(b.latest_change||'').localeCompare(a.latest_change||''):(a,b)=>b.change_count-a.change_count);

const html=rows.map(p=>
 '<button type="button" class="lead program-card '+(p.id===research.selected?'selected':'')+'" data-program="'+p.id+'" aria-pressed="'+(p.id===research.selected)+'">'+
 '<div class="lead-body"><div class="lead-top"><h3>'+rEscape(p.name)+'</h3><time>'+rEscape(ago(p.latest_change))+'</time></div>'+
 '<div class="change-pills"><span class="change-pill'+(p.code_change_count?'':' pill-zero')+'">'+rCount(p.code_change_count,'code change')+'</span><span class="change-pill'+(p.program_change_count?'':' pill-zero')+'">'+rCount(p.program_change_count,'policy change')+'</span></div>'+
 '<p class="lead-meta">'+rEscape(p.max_bounty==null?'Reward ceiling unknown':'Up to '+money(p.max_bounty))+' <span aria-hidden="true">·</span> '+rEscape(p.lifecycle)+'</p>'+
 '<p class="lead-stack">'+rEscape([...new Set([...p.fit.chains,...p.fit.languages])].join(' · ')||'Stack unclassified')+'</p></div></button>'
 ).join('')||(research.programs.length?'<p class="load-state">No programs match these filters. Try another search or reset the filters.</p>':(research.loadError?retryCardHtml(research.loadError):'<p class="load-state">No monitored programs yet. Load sources with Refresh sources above.</p>'));

const countEl=document.getElementById('program-count'),countText=rows.length+' program'+(rows.length===1?'':'s');
if(countEl.__text!==countText){countEl.textContent=countText;countEl.__text=countText}

if(list.__html!==html){list.innerHTML=html;list.__html=html}
bindRetryCard(list);

document.querySelectorAll('[data-program]').forEach(button=>{button.setAttribute('aria-pressed',String(Number(button.dataset.program)===research.selected));button.onclick=()=>researchSelect(Number(button.dataset.program))});
list.scrollTop=scroll;if(focused)Array.from(list.querySelectorAll('[data-program]')).find(button=>button.dataset.program===focused)?.focus({preventScroll:true});

}

async function researchLoad(){if(research.loading)return false;research.loading=true;try{const response=await apiFetch('/api/programs');const data=await response.json();if(!response.ok)throw Error(data.error||'Unable to load programs');research.programs=data.programs;research.revision=data.revision??null;research.loadError=null;window.CHANGE_STATS=data.change_stats;updateStats(data.stats);for(const [key,field] of [['chain','chains'],['language','languages'],['type','protocol_types']]){const el=document.getElementById('filter-'+key),current=el.value;const tags=[...new Set(data.programs.flatMap(p=>p.fit[field]))].sort();const options='<option value="">All '+({chain:'chains',language:'languages',type:'protocol types'}[key])+'</option><option value="__unknown">Unclassified</option>'+tags.map(tag=>'<option>'+rEscape(tag)+'</option>').join('');if(el.__html!==options){el.innerHTML=options;el.__html=options;if(current==='__unknown'||tags.includes(current))el.value=current}}researchRender();if(research.selected!=null){if(research.revision!==null&&research.detailRevision===research.revision)return true;return await researchSelect(research.selected,{background:true})}return true}catch(error){research.loadError=error.message;const countEl=document.getElementById('program-count');if(countEl.__text!==error.message){countEl.textContent=error.message;countEl.__text=error.message}if(!research.programs.length){const list=document.getElementById('program-list');const alertHtml=retryCardHtml(error.message);if(list.__html!==alertHtml){list.innerHTML=alertHtml;list.__html=alertHtml}bindRetryCard(list)}return false}finally{research.loading=false}}

for(const id of ['program-search','filter-chain','filter-language','filter-type','filter-lifecycle','filter-scoped','filter-open','filter-investigation','program-sort'])document.getElementById(id).addEventListener(id==='program-search'?'input':'change',()=>{setMobileView('list');researchRender()});

function researchRules(value){if(typeof value==='string')return '<p>'+rEscape(value||'Payout conditions unrecorded')+'</p>';const entries=Object.entries(value&&typeof value==='object'?value:{});if(!entries.length)return '<p class="muted">Unknown</p>';const labels={kyc:'KYC required',pay_to_submit:'Paid submission',proof_of_concept:'Proof of concept',primacy:'Eligibility policy',rewards_token:'Reward currency',invite_only:'Invitation required',responsible_publication:'Publication policy',immunefi_standard:'Platform standard rules'};return '<ul>'+entries.map(([key,item])=>'<li><b>'+rEscape(labels[key]||key.replaceAll('_',' '))+'</b>: '+rEscape(typeof item==='boolean'?(item?'Yes':'No'):item==null?'Unknown':String(item).replaceAll('_',' '))+'</li>').join('')+'</ul>'}
const rCard=(title,body)=>'<section class="card"><h3>'+title+'</h3>'+body+'</section>';

function changeListHtml(events){return events.length?events.map(e=>'<details class="observed-change" data-view-key="change:'+Number(e.id)+'"><summary>'+rEscape(e.entity)+' · '+rEscape(window.KIND_LABELS?.[e.kind]?.[2]||e.kind.replaceAll('_',' ').toLowerCase())+' · '+rEscape(ago(e.detected_at))+'</summary>'+changeBodyHtml(e)+'</details>').join(''):'<p class="muted">No changes recorded yet.</p>'}

function onchainHtml(d){
 const check=d.onchain;if(!check?.assets?.length)return '';
 const running=check.state==='running',missing=[...new Set(check.assets.filter(a=>!a.configured).map(a=>a.rpc_env))];
 const disabled=running||!check.configured_count||!check.has_changes||d.lifecycle!=='active';
 const message=running?'Checking '+(check.completed||0)+'/'+check.assets.length+' scoped assets…':check.checked_at?'Last check '+new Date(check.checked_at).toLocaleString()+(check.error_count?' · '+check.error_count+' checks need attention':''):check.assets.length+' scoped EVM asset'+(check.assets.length===1?'':'s');
 const labels={baseline:'Baseline saved',changed:'Implementation changed',unchanged:'Unchanged',unsupported:'No supported implementation slot',no_contract:'No contract at this address',error:'Check failed'};
 const rows=check.assets.map(a=>{const r=a.result;return '<li><b>'+rEscape(a.chain)+'</b> · <code>'+rEscape(a.address)+'</code><br>'+rEscape(r?labels[r.status]||r.status:'Not checked')+(r?.implementation?'<br>Last observed implementation: <code>'+rEscape(r.implementation)+'</code>':'')+(r?.changed?'<br>Previous implementation: <code>'+rEscape(r.previous_implementation||'empty slot')+'</code>':'')+(r?.error?'<p class="bad">'+rEscape(r.error)+'</p>':'')+'</li>'}).join('');
 return rCard('On-chain check','<p>'+rEscape(message)+'</p><button data-check-onchain '+(disabled?'disabled':'')+'>'+(running?'Checking…':'Check on-chain')+'</button><p data-onchain-feedback role="status"></p><p class="muted">Checks only this program. No automatic on-chain polling. The first successful check saves a baseline.</p>'+(d.lifecycle!=='active'?'<p class="muted">This program is not active.</p>':!check.has_changes?'<p class="muted">Available after a code or program change is recorded.</p>':'')+(missing.length?'<p class="muted">RPC setup needed: <code>'+rEscape(missing.join(', '))+'</code>. Set these in .env and restart.</p>':'')+(check.error?'<p class="bad">'+rEscape(check.error)+'</p>':'')+'<details data-view-key="onchain-assets"><summary>Scoped addresses ('+check.assets.length+')</summary><ul>'+rows+'</ul></details>');
}

function bindOnchain(d,box){const button=box.querySelector('[data-check-onchain]');if(!button)return;
 button.onclick=async()=>{button.disabled=true;const status=box.querySelector('[data-onchain-feedback]');status.textContent='Queuing this program’s check…';
  try{const response=await apiFetch('/api/programs/'+d.id+'/onchain',{method:'POST'}),result=await response.json();if(!response.ok)throw Error(result.error||'Unable to queue on-chain check');if(research.selected===d.id)await researchSelect(d.id,{background:true})}
  catch(error){if(research.selected===d.id){status.textContent=error.message;button.disabled=false}}
 };
}

function researchDossier(d){const policy=d.policy||{},rewards=policy.rewards||{};const tiers=[];for(const [category,rows]of Object.entries(rewards))for(const [severity,tier]of Object.entries(rows||{}))tiers.push('<li>'+rEscape(category+' / '+severity)+': '+rEscape(tier.flat!=null?money(tier.flat):[tier.min,tier.max].filter(x=>x!=null).map(money).join(' – ')||'Unspecified')+'</li>');

return '<div class="dossier-intro"><p class="dossier-kicker">PROGRAM / EVIDENCE</p><h2>'+rEscape(d.name)+'</h2><p>'+rEscape(d.platform+' · '+d.lifecycle)+' · '+rLink(d.url,'Program rules')+'</p><p class="muted">Policy observed '+rEscape(d.policy_observed_at||'unknown')+'</p></div>'+onchainHtml(d)+rCard('Worth investigating?', '<p class="big">'+rEscape(policy.max_bounty==null?'Reward ceiling unknown':money(policy.max_bounty))+'</p>'+(tiers.length?'<ul>'+tiers.join('')+'</ul>':'<p>Reward tiers unknown.</p>')+'<details data-view-key="impacts"><summary>Covered impacts ('+(policy.impacts||[]).length+')</summary>'+rList(policy.impacts)+'</details><h4>Payout conditions</h4>'+researchRules(d.payout_conditions)+'<h4>Available funds</h4>'+(d.funds?'<p>'+rEscape(d.funds.amount+' '+(d.funds.currency||'currency unspecified'))+' · observed '+rEscape(d.funds.observed_at)+' · '+rLink(d.funds.url,'Evidence')+'</p><p class="muted">Recorded observation; not a guarantee of payout or current balance.</p>':'<p class="muted">Unverified. Reward ceiling does not establish available funds.</p>'))+rCard('Code changes',changeListHtml(d.code_changes))+rCard('Program changes',changeListHtml(d.program_changes))+rCard('Stack', '<p>'+rEscape([...new Set([...d.fit.chains,...d.fit.languages])].join(' · ')||'Unclassified')+'</p>')+rCard('Download file diffs',(d.code_changes.some(hasFileDiffs)?'<p><a href="/api/programs/'+d.id+'/package">Download file diffs (.zip)</a></p>':'<p class="muted">No file patches recorded for this program yet.</p>')+'<p class="muted">Recorded per-file patches with revision details. Missing and truncated patches are listed in the archive.</p><h4>Tracked repositories</h4><ul>'+d.repositories.map(repo=>'<li>'+rLink(repo.url,repo.repository)+'</li>').join('')+'</ul>');

}

function programViewKey(details){const owner=details.closest('.observed-change');return (owner&&owner!==details?owner.dataset.viewKey+'/':'')+details.dataset.viewKey}

function captureProgramView(box){
 const details=Array.from(box.querySelectorAll('details[data-view-key]'));
 const bounds=box.getBoundingClientRect(),top=Math.max(bounds.top,0),bottom=Math.min(bounds.bottom,window.innerHeight);
 const visible=details.filter(el=>{const r=el.getBoundingClientRect();return el.getClientRects().length&&r.bottom>top&&r.top<bottom});
 const anchor=visible.sort((a,b)=>Math.abs(a.getBoundingClientRect().top-top)-Math.abs(b.getBoundingClientRect().top-top))[0];
 const active=document.activeElement;
 return {open:new Map(details.map(el=>[programViewKey(el),el.open])),
  patches:new Map(Array.from(box.querySelectorAll('.diff-code')).map(el=>[programViewKey(el.closest('details[data-view-key]')),{top:el.scrollTop,left:el.scrollLeft}])),
  top:box.scrollTop,pageX:window.scrollX,pageY:window.scrollY,
  anchor:anchor?{key:programViewKey(anchor),top:anchor.getBoundingClientRect().top}:null,
  focused:box.contains(active)&&active.tagName==='SUMMARY'?programViewKey(active.parentElement):null};
}

function restoreProgramView(box,view){
 const details=Array.from(box.querySelectorAll('details[data-view-key]'));
 details.forEach(el=>{const key=programViewKey(el);if(view.open.has(key))el.open=view.open.get(key)});
 box.querySelectorAll('.diff-code').forEach(el=>{const scroll=view.patches.get(programViewKey(el.closest('details[data-view-key]')));if(scroll){el.scrollTop=scroll.top;el.scrollLeft=scroll.left}});
 box.scrollTop=view.top;window.scrollTo(view.pageX,view.pageY);
 const anchor=view.anchor&&details.find(el=>programViewKey(el)===view.anchor.key);
 if(anchor){const delta=anchor.getBoundingClientRect().top-view.anchor.top;if(box.scrollHeight>box.clientHeight+1)box.scrollTop+=delta;else window.scrollBy(0,delta)}
 if(view.focused)details.find(el=>programViewKey(el)===view.focused)?.querySelector('summary')?.focus({preventScroll:true});
}

async function researchSelect(id,{background=false}={}){
 if(background&&(research.selected!==id||research.detailLoading))return false;
 if(!background){research.selected=id;research.detailRevision=null;researchRender();if(typeof setMobileView==='function')setMobileView('detail')}
 const request=++research.request,revisionAtRequest=research.revision;research.detailLoading=request;
 const box=document.getElementById('program-dossier');box.setAttribute?.('aria-busy','true');
 if(!background){research.renderedProgram=null;research.detailHtml=null;box.innerHTML='<p class="muted" role="status">Loading program evidence…</p>';focusPanel('program-dossier')}
 try{
  const response=await apiFetch('/api/programs/'+id),data=await response.json();
  if(!response.ok)throw Error(data.error||'Unable to load program');
  if(request!==research.request||research.selected!==id)return false;
  const html=researchDossier(data);
  if(!background||research.renderedProgram!==id||research.detailHtml!==html){
   const view=background&&research.renderedProgram===id?captureProgramView(box):null;
   box.innerHTML='<button class="dossier-back" data-back-programs>← Back to program list</button><p data-program-refresh-status class="muted" role="status"></p>'+html;
   box.querySelector('[data-back-programs]')?.addEventListener('click',()=>{if(typeof setMobileView==='function')setMobileView('list');focusPanel('program-search')});
   bindOnchain(data,box);research.renderedProgram=id;research.detailHtml=html;
   if(view)restoreProgramView(box,view);else if(!background){box.scrollTop=0;focusPanel('program-dossier')}
  }
  research.detailRevision=revisionAtRequest;
  const status=box.querySelector('[data-program-refresh-status]');if(status)status.textContent='';
  return true;
 }catch(error){
  if(request===research.request){
   if(background){const status=box.querySelector('[data-program-refresh-status]');if(status)status.textContent='Unable to refresh this program; retrying automatically.'}
   else{box.innerHTML='<div class="load-state" role="alert"><p>'+rEscape(error.message)+'</p><button data-retry-dossier>Try again</button></div>';box.querySelector('[data-retry-dossier]')?.addEventListener('click',()=>researchSelect(id))}
  }
  return false;
 }finally{if(request===research.request){research.detailLoading=null;box.setAttribute?.('aria-busy','false')}}
}

document.getElementById('reset-program-filters')?.addEventListener('click',()=>{setMobileView('list');for(const id of ['program-search','filter-chain','filter-language','filter-type','filter-investigation'])document.getElementById(id).value='';document.getElementById('filter-lifecycle').value='active';document.getElementById('program-sort').value='recent';document.getElementById('filter-open').checked=true;document.getElementById('filter-scoped').checked=false;research.programs.length?researchRender():researchLoad()});


researchLoad();

setInterval(()=>{if(!document.hidden)researchLoad()},30000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)researchLoad()});


if(typeof document!=='undefined'&&document.addEventListener){
 document.addEventListener('keydown',e=>{
  if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){
   e.preventDefault();document.getElementById('program-search')?.focus();return;
  }
  const tag=document.activeElement?.tagName;
  if(e.key==='Escape'&&typeof toggleDrawer==='function'){
   const drawer=document.getElementById('failures');
   if(drawer?.classList?.contains('open')){e.preventDefault();toggleDrawer()}
  }
  if(['INPUT','SELECT','TEXTAREA'].includes(tag)||document.activeElement?.isContentEditable)return;
  if(e.key==='/'){e.preventDefault();document.getElementById('program-search')?.focus();return;}
  if(e.key.toLowerCase()==='t'&&!e.metaKey&&!e.ctrlKey&&!e.altKey&&typeof applyTheme==='function'){
   e.preventDefault();
   const cur=document.documentElement?.getAttribute?.('data-theme')==='light'?'dark':'light';
   applyTheme(cur);return;
  }
  if(['ArrowDown','ArrowUp','j','k'].includes(e.key)){
   if(e.repeat)return;
   const dossier=document.getElementById('program-dossier');
   // Arrow keys stay native while the dossier has focus so it can scroll itself;
   // J/K keep working everywhere.
   if((e.key==='ArrowDown'||e.key==='ArrowUp')&&dossier?.contains?.(document.activeElement))return;
   const cards=Array.from(document.querySelectorAll('[data-program]'));
   if(!cards.length)return;
   e.preventDefault();
   const idx=cards.findIndex(b=>Number(b.dataset.program)===research.selected);
   const step=(e.key==='ArrowDown'||e.key==='j')?1:-1;
   const nextIdx=idx<0?0:Math.max(0,Math.min(cards.length-1,idx+step));
   const target=cards[nextIdx];
   if(!target)return;
   target.scrollIntoView?.({block:'nearest',behavior:'instant'});
   if(Number(target.dataset.program)!==research.selected)researchSelect(Number(target.dataset.program));
  }
 });
}
