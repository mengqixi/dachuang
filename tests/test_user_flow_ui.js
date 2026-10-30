// Run the actual inline async handlers with controlled, non-network responses.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync('index.html','utf8');
const extract = (start,end) => html.slice(html.indexOf(start),html.indexOf(end));
const source = [
  extract('function resetUserSubmissionState(','function renderUploadSummary('),
  extract('async function analyzeCurrentSubmission(','async function runUserAiAssist('),
  extract('async function runUserAiAssist(','function waitMs('),
  extract('async function loadReport(','function buildReportDocument('),
].join('\n');
const defer = () => {let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve}};
function context(){
  const elements={};
  const c={currentSubmissionId:'A',userResultRevision:0,currentAnalysis:{analysis_trace:{analysis_id:'ana-A'}},
    currentExternalAnalysis:null,currentReport:'old report',currentReportPayload:{submission:{id:'A'}},lastRiskReasons:[{id:1}],
    pageLoaded:new Set(['report']),obj:x=>x||{},toast:()=>{},rendered:[],errors:[],
    document:{getElementById:id=>elements[id]||=( {innerHTML:'old',textContent:'old',classList:{toggle(){}}} )},
    api:async()=>({ok:true,data:{available:true}}),apiWithTimeout:async()=>{throw Error('unexpected provider request')},
    resetExternalAiDatasetResult(){c.currentExternalAnalysis=null},
    renderAnalysis(d){c.currentAnalysis=d;c.rendered.push(d)},
    renderExternalAiResult(d){c.rendered.push(d)},renderReportStructured(d){c.currentReportPayload=d;c.rendered.push(d)},
    renderUserAiFailure(m){c.errors.push(m)},
  };
  c.reportBox=c.document.getElementById('reportBox');
  vm.createContext(c);vm.runInContext(source,c);return c;
}
async function aiResultAfterSwitch(){
  const c=context(),entered=defer(),pending=defer();
  c.apiWithTimeout=async url=>{assert(url.includes('/A/'));entered.resolve();return pending.promise};
  const task=c.runUserAiAssist();await entered.promise;
  c.resetUserSubmissionState('B');c.currentAnalysis={analysis_trace:{analysis_id:'ana-B'}};
  c.rendered.length=0;
  pending.resolve({ok:true,data:{submission_id:'A',analysis_id:'ana-A',advice:{summary:'old'}}});await task;
  assert.equal(c.currentExternalAnalysis,null);assert.equal(c.rendered.length,0);
  assert.equal(c.currentReportPayload,null);assert.equal(c.currentReport,'');assert.equal(c.pageLoaded.has('report'),false);
}
async function switchBeforeStatusReturns(){
  const c=context(),status=defer();let calls=0;c.api=()=>status.promise;c.apiWithTimeout=async()=>{calls++};
  const task=c.runUserAiAssist();c.resetUserSubmissionState('B');
  status.resolve({ok:true,data:{available:true}});await task;assert.equal(calls,0);
}
async function lateReportAndDetectionAreIgnored(){
  for(const method of ['loadReport','analyzeCurrentSubmission']){
    const c=context(),response=defer();c.api=()=>response.promise;
    const task=c[method]();c.resetUserSubmissionState('B');c.rendered.length=0;
    response.resolve({ok:true,data:{submission:{id:'A'},analysis:{analysis_trace:{analysis_id:'ana-A'}}}});
    await task;assert.equal(c.currentReportPayload,null);assert.equal(c.rendered.length,0);
  }
}
async function unchangedSubmissionAcceptsMatchingAiOnly(){
  const c=context();c.apiWithTimeout=async()=>({ok:true,data:{submission_id:'A',analysis_id:'ana-A',advice:{summary:'current'}}});
  await c.runUserAiAssist();assert.equal(c.currentExternalAnalysis.advice.summary,'current');
  const other=context();other.apiWithTimeout=async()=>({ok:true,data:{submission_id:'A',analysis_id:'old-version',advice:{summary:'stale'}}});
  await other.runUserAiAssist();assert.equal(other.currentExternalAnalysis,null);assert.equal(other.errors.length,1);
}
async function adaptiveReviewContinuesOnlyPendingRows(){
  const c=context();let calls=0;
  c.apiWithTimeout=async(url,options)=>{
    assert.equal(JSON.parse(options.body).adaptive_review,true);calls++;
    return{ok:true,data:{submission_id:'A',analysis_id:'ana-A',advice:{summary:'review'},
      review_scope:{reviewed:calls===1?24:26,total:26,complete:calls===2}}};
  };
  await c.runUserAiAssist();assert.equal(calls,2);assert.equal(c.currentExternalAnalysis.review_scope.reviewed,26);
}
function aiResultShowsLocalIpAndConciseFooter(){
  const c=context();c.arr=x=>Array.isArray(x)?x:[];
  c.esc=x=>String(x??'').replaceAll('<','&lt;').replaceAll('>','&gt;');
  c.riskLevelText=x=>x;c.aiListHtml=()=>'';
  c.currentAnalysis={risk_ranking:[{id:15,ip:'198.51.100.15'}]};
  vm.runInContext(extract('function infoButton(','function aiListHtml('),c);
  vm.runInContext(extract('function aiDatasetResultHtml(','function aiTrainingResultHtml('),c);
  const rendered=c.aiDatasetResultHtml({model:'gpt-6.1-sol',generated_at:'2026-10-29',
    advice:{summary:'summary',confidence_note:'long explanation'},assisted_summary:{reviewed:1},
    assisted_decisions:[{sample_id:15,local_risk_level:'high',combined_risk_level:'high',recommended_action:'Check <script>'}]},true);
  assert(rendered.includes('198.51.100.15'));assert(rendered.includes('样本 15'));
  assert(rendered.includes('Check &lt;script&gt;'));assert(!rendered.includes('Check <script>'));
  const footer=rendered.slice(rendered.lastIndexOf('ai-status-line'));
  assert(footer.includes('gpt-6.1-sol'));assert(!footer.includes('long explanation'));
}
(async()=>{
  for(const script of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi))new vm.Script(script[1]);
  await aiResultAfterSwitch();await switchBeforeStatusReturns();await lateReportAndDetectionAreIgnored();await unchangedSubmissionAcceptsMatchingAiOnly();
  await adaptiveReviewContinuesOnlyPendingRows();aiResultShowsLocalIpAndConciseFooter();
  console.log('User flow UI: stale AI, status race, local-analysis race, report race, reset and matching-version checks passed');
})().catch(error=>{console.error(error);process.exitCode=1});
