const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('index.html','utf8');
const extract=(a,b)=>html.slice(html.indexOf(a),html.indexOf(b));
function setup(){
 const modal={hidden:true,dataset:{},querySelector:()=>({focus(){}})},body={innerHTML:''};
 const elements={submissionDetailModal:modal,submissionDetailBody:body};
 const c={obj:x=>x||{},arr:x=>Array.isArray(x)?x:[],esc:x=>String(x??'').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),
  fmtTime:x=>x||'-',shortText:x=>x||'',riskSummaryTags:()=> '风险统计',privacyRiskBadge:()=>'',reviewStatusBadge:()=>'',lifecycleBadge:()=>'',submissionSecurityFields:()=>'',riskLevelText:x=>x,infoButton:()=>'<button>说明</button>',
  aiDatasetResultHtml:r=>'<p>'+r.advice.summary+'</p>',document:{getElementById:id=>elements[id]},
  openMiniModal:()=>modal.hidden=false,toast(){},
  invalidateSubmissionAndDataPages(){},loadSubmissionsData:async()=>{},
  api:async()=>({ok:true,data:{id:'A',analysis:{total:30,analyzed_at:'date'},external_analysis:{advice:{summary:'用户端已有结论'},generated_at:'date'}}}),
  showExternalAiResultModal:r=>c.shown=r,requestAdaptiveAi:async()=>{c.paid++;return{ok:true,data:{advice:{summary:'新增结论'}}}},paid:0,
 };
 vm.createContext(c);vm.runInContext(extract('let submissionRows=[];','function submissionSecurityFields('),c);
 vm.runInContext(extract('async function analyzeSubmission(','async function markTrainable('),c);
 return {c,modal,body};
}
(async()=>{
 const {c,modal,body}=setup();
 const list=c.renderSubmissionRows([{id:'A',filename:'first.csv',upload_time:'2026-10-30',allowed_actions:['mark_trainable','reject'],external_analysis:{}}]);
 assert(list.includes('showSubmissionDetail'));assert(!list.includes('onclick="analyzeSubmission'));assert(!list.includes('onclick="runAdminSubmissionAi'));
 assert(list.includes('允许训练'));assert(list.includes('拒绝'));
 assert(list.includes('>接受</button>'));assert(list.includes('submission-row-actions'));
 assert.equal((list.match(/class="submission-actions/g)||[]).length,1);
 await c.showSubmissionDetail(0);assert.equal(modal.hidden,false);
 assert(body.innerHTML.includes('普通分析'));assert(body.innerHTML.includes('AI 复核 · 已保存'));assert(!body.innerHTML.includes('用户端已有结论'));
 assert.equal((body.innerHTML.match(/风险统计/g)||[]).length,1);
 assert(body.innerHTML.includes('<summary>查看明细</summary>'));assert(!body.innerHTML.includes('ai-visuals'));
 assert.equal((body.innerHTML.match(/<details /g)||[]).length,1);
 c.setSubmissionDetailTab('ai');assert(body.innerHTML.includes('用户端已有结论'));assert(!body.innerHTML.includes('普通分析'));
 assert.equal((body.innerHTML.match(/<summary>/g)||[]).length,1);
 c.setSubmissionDetailTab('local');
 assert(body.innerHTML.includes('data-submission-id="A"'));assert(!body.innerHTML.includes("analyzeSubmission('A'"));
 await c.runAdminSubmissionAi('A');assert.equal(c.paid,0);assert(body.innerHTML.includes('用户端已有结论'));assert.equal(c.shown,undefined);
 await c.runAdminSubmissionAi('A',null,true);assert.equal(c.paid,1);
 let request;
 c.apiWithTimeout=async(url,options)=>{request=JSON.parse(options.body);return{ok:true,data:{privacy_risk:{},attack_risk:{}}}};
 await c.analyzeSubmission('A');assert.equal(request.limit,1000);
 let resolve;c.api=()=>new Promise(r=>resolve=r);
 const task=c.runAdminSubmissionAi('A');modal.hidden=true;
 resolve({ok:true,data:{}});await task;assert.equal(c.paid,1);
 console.log('Submission detail: review buttons outside, analysis inside, user AI reuse without provider, explicit continuation and close-race guards passed');
})().catch(e=>{console.error(e);process.exitCode=1});
