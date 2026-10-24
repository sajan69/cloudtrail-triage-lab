'use strict';
const token = location.hash.slice(1);
const $ = id => document.getElementById(id);
const filterKeys = ['account','principal','region','source','started_at','ended_at'];
let offset = 0, evidenceOffset = 0, selected = null;
function params(keys) { const p = new URLSearchParams(); for (const key of keys) if ($(key).value) p.set(key,$(key).value); return p; }
async function request(path) {
  const response = await fetch(path,{headers:{'X-Triage-Token':token},cache:'no-store'});
  if (!response.ok) { const body = await response.json(); throw new Error(body.error || 'Request failed'); }
  return response;
}
async function json(path) { return (await request(path)).json(); }
function error(exception) { $('error').textContent = 'Unable to load: ' + exception.message; $('error').hidden=false; $('status').textContent='Request failed. Check filters or reopen the full local access URL.'; }
function run(action) { $('error').hidden=true; return action().catch(error); }
function populate(id,values,label) { const old=$(id).value; $(id).replaceChildren(new Option(label,''),...values.map(v=>new Option(v,v))); $(id).value=old; }
function table(container,events,caption) {
  const fields=['event_time','event_name','event_source','region','principal','error_code','event_id'];
  const root=document.createElement('table'), title=document.createElement('caption'); title.textContent=caption; root.append(title);
  const head=document.createElement('thead'), row=document.createElement('tr');
  for (const field of fields) { const cell=document.createElement('th');cell.scope='col';cell.textContent=field.replaceAll('_',' ');row.append(cell); }
  head.append(row);root.append(head);const body=document.createElement('tbody');
  for (const event of events) { const tr=document.createElement('tr');for(const field of fields){const td=document.createElement('td');td.textContent=event[field]??'—';td.title=event[field]??'';tr.append(td);}body.append(tr); }
  root.append(body);$(container).replaceChildren(root);
}
function findingParams() { return params(['account','principal','started_at','ended_at','rule','severity']); }
async function loadFindings() {
  const data=await json('/api/findings?'+findingParams());$('finding-count').textContent=data.findings.length;
  $('findings').replaceChildren();
  if(!data.findings.length){const p=document.createElement('p');p.textContent='No matching findings. This does not establish that the imported activity is safe.';$('findings').append(p);}
  for(const finding of data.findings){const button=document.createElement('button');button.className='finding';button.dataset.id=finding.id;button.setAttribute('aria-pressed',String(selected===finding.id));
    const heading=document.createElement('strong');heading.textContent=finding.rule_id+' · '+finding.severity+' priority';
    for(const value of [finding.started_at,finding.reason,finding.principal]){const line=document.createElement('span');line.textContent=value;button.append(line);}button.prepend(heading);
    button.addEventListener('click',()=>run(async()=>{selected=finding.id;evidenceOffset=0;for(const b of document.querySelectorAll('.finding'))b.setAttribute('aria-pressed',String(b.dataset.id===selected));await loadEvidence();$('evidence-heading').focus();}));$('findings').append(button);
  }
}
async function loadTimeline(){const p=params(filterKeys);p.set('limit','100');p.set('offset',String(offset));const data=await json('/api/timeline?'+p);table('timeline',data.events,'Filtered events in UTC order');$('page').textContent=data.total?`${offset+1}–${offset+data.events.length} of ${data.total}`:'0 matching events';$('previous').disabled=offset===0;$('next').disabled=offset+100>=data.total;}
async function loadEvidence(){if(!selected)return;const p=new URLSearchParams({id:selected,limit:'100',offset:String(evidenceOffset)});const data=await json('/api/evidence?'+p);$('evidence-hint').textContent=data.finding.rule_id+' · full finding context';$('finding-detail').textContent=data.finding.reason+'\n\n'+JSON.stringify(data.finding.metrics,null,2);table('evidence-table',data.events,'Events supporting the selected finding');$('evidence-page').textContent=`${evidenceOffset+1}–${evidenceOffset+data.events.length} of ${data.total}`;$('evidence-prev').disabled=evidenceOffset===0;$('evidence-next').disabled=evidenceOffset+100>=data.total;for(const b of document.querySelectorAll('[data-export="evidence"]'))b.disabled=false;}
async function refresh(){if(!token)throw new Error('Access token missing from URL fragment');$('status').textContent='Reading local database…';const info=await json('/api/overview');$('event-count').textContent=info.events;$('account-count').textContent=info.accounts;$('unknown-count').textContent=info.uncorrelatable;populate('account',info.accounts_available,'All accounts');populate('source',info.sources_available,'All services');populate('region',info.regions_available,'All Regions');await loadFindings();await loadTimeline();$('status').textContent='Local data loaded · all timestamps are UTC';}
$('filters').addEventListener('submit',event=>{event.preventDefault();offset=0;run(refresh);});
$('reset-filters').addEventListener('click',()=>{$('filters').reset();offset=0;run(refresh);});
$('previous').addEventListener('click',()=>{offset=Math.max(0,offset-100);run(loadTimeline);});$('next').addEventListener('click',()=>{offset+=100;run(loadTimeline);});
$('evidence-prev').addEventListener('click',()=>{evidenceOffset=Math.max(0,evidenceOffset-100);run(loadEvidence);});$('evidence-next').addEventListener('click',()=>{evidenceOffset+=100;run(loadEvidence);});
for(const button of document.querySelectorAll('[data-export]'))button.addEventListener('click',()=>run(async()=>{const kind=button.dataset.export,format=button.dataset.format;const p=kind==='events'?params(filterKeys):kind==='findings'?findingParams():new URLSearchParams({id:selected});p.set('kind',kind);p.set('format',format);const response=await request('/api/export?'+p);const url=URL.createObjectURL(await response.blob());const a=document.createElement('a');a.href=url;a.download=`triage-${kind}.${format}`;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}));
run(refresh);
