const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('index.html','utf8');
function setup(){
  const els={},requests=[];
  const element=id=>els[id]||=( {innerHTML:'',textContent:'',value:'',hidden:false,setAttribute(k,v){this[k]=v;}} );
  const c={document:{getElementById:element},obj:x=>x||{},arr:x=>Array.isArray(x)?x:[],
    esc:x=>String(x??'').replaceAll('<','&lt;'),fmtTime:x=>x,fmtCompactTime:x=>x,riskLevelText:x=>x,
    encodeURIComponent,auditState:{tab:'events',requestId:0,eventOffset:0,visitOffset:0,events:[],visits:[]},
    api:async url=>{requests.push(url);return{ok:true,data:{events:[{event_type:'path_scan',risk_level:'high',ip:'198.51.100.2'}],total:41}}},
  };
  for(const id of ['auditRiskFilter','auditIpFilter','auditPathFilter','auditTypeFilter','auditLimit','auditFilterSummary',
    'eventTable','visitTable','eventPageInfo','visitPageInfo'])c[id]=element(id);
  c.auditRiskFilter.value='medium,high,critical';c.auditLimit.value='20';
  element('auditFilters').hidden=true;
  vm.createContext(c);
  vm.runInContext(html.slice(html.indexOf('function selectAuditTab('),html.indexOf('// Compatibility names')),c);
  vm.runInContext(html.slice(html.indexOf('function pad2('),html.indexOf('function isSensitivePreviewKey(')),c);
  return {c,els,requests};
}
(async()=>{
  const {c,els,requests}=setup();
  assert(c.auditTimeCell('2026-10-30T12:00:06.123').includes('2026-10-30 12:00:06'));
  assert(c.auditTimeCell(null).includes('时间未记录'));
  assert(c.auditTimeCell('').includes('时间未记录'));
  assert(!c.auditTimeCell('<script>').includes('<script>'));
  await c.loadAudit();assert.equal(requests.length,1);
  let query=new URL('http://local'+requests[0]).searchParams;
  assert.equal(query.get('risk_level'),'medium,high,critical');assert.equal(query.get('exclude_event_type'),'site_visit');
  assert.equal(c.eventPageInfo.textContent,'第 1/3 页 · 共 41 条');
  await c.pageAudit(1,'events');assert.equal(new URL('http://local'+requests[1]).searchParams.get('offset'),'20');
  c.auditTypeFilter.value='path_scan';
  await c.selectAuditTab('visits');query=new URL('http://local'+requests[2]).searchParams;
  assert.equal(query.get('event_type'),'site_visit');assert.equal(query.get('risk_level'),'');
  assert(els.auditRiskField.hidden);assert(els.auditTypeField.hidden);assert(els.auditEventsPane.hidden);
  await c.selectAuditTab('events');
  assert(!els.auditRiskField.hidden);assert.equal(c.auditState.eventOffset,0); // changed event type resets page
  c.toggleAuditFilters();assert.equal(els.auditFilterButton['aria-expanded'],'true');
  c.toggleAuditFilters();assert.equal(els.auditFilterButton['aria-expanded'],'false');
  // Superseded slow responses cannot overwrite the active tab or its summary.
  const pending=[];c.api=url=>new Promise(resolve=>pending.push({url,resolve}));
  const old=c.loadAudit(),current=c.selectAuditTab('visits');
  pending[1].resolve({ok:true,data:{events:[{event_type:'site_visit',ip:'new'}],total:1}});await current;
  pending[0].resolve({ok:true,data:{events:[{event_type:'path_scan',ip:'stale'}],total:500}});await old;
  assert(c.visitTable.innerHTML.includes('new'));assert(!c.eventTable.innerHTML.includes('stale'));
  c.api=async()=>({ok:false,error:'offline'});await c.loadAudit();
  assert(c.visitTable.innerHTML.includes('读取失败'));assert(els.visitNextButton.disabled);
  const section=html.slice(html.indexOf('<section class="page" id="pg-audit"'),html.indexOf('<section class="page" id="pg-login"'));
  assert.equal((section.match(/class="panel"/g)||[]).length,1);
  for(const id of ['auditMetrics','auditVisuals','suspiciousIpTable'])assert(!section.includes(`id="${id}"`));
  assert(section.includes('id="auditFilters" hidden'));
  console.log('Audit UI: one panel, attention default, unfiltered visits, one request, paging, races, filters and failures passed');
})().catch(e=>{console.error(e);process.exit(1)});
