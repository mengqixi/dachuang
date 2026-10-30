const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('index.html','utf8');
const extract=(start,end)=>html.slice(html.indexOf(start),html.indexOf(end));
const esc=x=>String(x??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
function context(){
  const elements={trainingRunButton:{innerHTML:'开始对比训练',disabled:false}};
  const c={obj:x=>x&&typeof x==='object'?x:{},arr:x=>Array.isArray(x)?x:[],esc,
    document:{getElementById:id=>elements[id]||null},currentDatasetSourceId:'source',
    currentDatasetSource:{name:'数据'},currentPreparation:{preparation_id:'prep'},
    trainingCompareState:{local:{version:'c1',accuracy:.8},federated:{version:'f1',accuracy:.79}},
    trainingAiContextKey:'',trainingAiBusy:false,fullTrainingBusy:false,currentTrainingAiComparison:null,
    trainingCompareBox:{innerHTML:'',hidden:false},aggregationVisualBox:{innerHTML:''},trainingResultSummary:{innerHTML:''},
    chartNumber:x=>x===undefined||x===null?null:Number(x),lossDisplay:x=>x||'--',optionalMetricDisplay:x=>x||'--',
    trainingMetricsComparable:()=>true,trainingValidationInfo:()=>({text:'共享留出集',warning:''}),
    pairedMetricsVisual:()=>'<div>图表</div>',aggregationMethodLabel:()=> '安全聚合',
    renderTrainingChart(){},renderModelVersionCompareChart(){},renderFederatedTrainingDetails(){},
    infoButton:()=>'<button>i</button>',datasetDisplayName:()=> '数据',federatedNodeLabel:x=>x,
    renderTrainingCompare(){c.renderCount++},renderCount:0,toast(){},
    openWorkspaceDetail(title,body){c.modal={title,body}},showExternalAiResultModal(data){c.shown=data},
    URLSearchParams,encodeURIComponent,api:async()=>({ok:true,data:{}}),
    ensureTrainingSource:async()=>{},loadTrainingRecords:async()=>{},loadDatasetSourcesData:async()=>{},
    processSystemDatasetImpl:async()=>({ok:false,error:'标签不足'}),clearAdminCache(){},
  };
  vm.createContext(c);
  vm.runInContext(extract('function renderAggregationVisual(','function renderTrainingChart('),c);
  vm.runInContext(extract('function renderTrainingCompare(','function trainLimit('),c);
  vm.runInContext(extract('function trainingComparisonBars(','async function ensureTrainingSource('),c);
  vm.runInContext(extract('function trainingAiStateKey(','async function loadDataProcessPage('),c);
  return {c,elements};
}
async function main(){
  const {c,elements}=context();
  c.renderTrainingCompare();
  assert(c.trainingCompareBox.innerHTML.includes('AI 解读本次对比'));
  assert(c.trainingCompareBox.innerHTML.includes('解读记录'));
  c.showTrainingDetails();
  assert(!c.modal.body.includes('AI 解读'));assert(c.modal.body.includes('训练样本'));
  assert(c.aggregationVisualBox.innerHTML.includes('<svg'));assert(!c.aggregationVisualBox.innerHTML.includes('fas'));
  for(const kind of ['idle','plain','secure','pending'])assert(c.aggregationIcon(kind).includes('viewBox="0 0 24 24"'));
  const chartCode=extract('function renderCompareChartCore(','function renderTrainingCompare(');
  assert(!chartCode.includes('summary-toolbar'));assert(!chartCode.includes('对比说明'));
  const saved={advice:{summary:'已保存 <script>',comparison_advice:'复核'},model:'test',generated_at:'2026-10-30'};
  let reads=0,writes=0;
  c.api=async url=>{assert(url.includes('local_version=c1'));reads++;return{ok:true,data:saved}};
  await c.loadSavedTrainingAiComparison();assert.equal(reads,1);
  assert(c.trainingCompareBox.innerHTML.includes('已保存 &lt;script&gt;'));
  c.apiWithTimeout=async()=>{writes++;throw Error('must not pay again')};
  await c.runTrainingAiComparison();assert.equal(writes,0);assert.equal(c.shown,saved);
  c.trainingCompareState.federated.version='f2';c.renderTrainingCompare();assert.equal(c.currentTrainingAiComparison,null);
  let resolve;
  c.api=()=>new Promise(r=>resolve=r);
  const loading=c.loadSavedTrainingAiComparison();
  c.trainingCompareState.federated.version='f3';c.renderTrainingCompare();
  resolve({ok:true,data:saved});await loading;assert.equal(c.currentTrainingAiComparison,null);
  c.apiWithTimeout=async()=>{writes++;return{ok:true,data:saved}};
  await c.runTrainingAiComparison();assert.equal(writes,1);
  assert(c.trainingCompareBox.innerHTML.includes('查看已存解读'));
  assert(c.trainingCompareBox.innerHTML.includes('2026-10-30'));
  // An earlier empty GET must not erase a newly completed paid review.
  const refresh=c.loadSavedTrainingAiComparison();
  c.currentTrainingAiComparison={...saved,generated_at:'new'};
  resolve({ok:true,data:{}});await refresh;
  assert.equal(c.currentTrainingAiComparison.generated_at,'new');
  await c.runAdminFullTraining();assert.equal(c.fullTrainingBusy,false);
  assert(c.trainingResultSummary.innerHTML.includes('本次训练未完成'));
  assert(c.trainingResultSummary.innerHTML.includes('标签不足'));
  assert(!c.aggregationVisualBox.innerHTML.includes('训练队列执行中'));
  assert.equal(elements.trainingRunButton.disabled,false);
  console.log('Training conclusion: outer AI result, saved restore, version/race guards, no duplicate calls, SVG icons, failure reset passed');
}
main().catch(e=>{console.error(e);process.exitCode=1});
