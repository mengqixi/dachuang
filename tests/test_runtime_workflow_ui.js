const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('index.html','utf8');
function setup(){
  const elements={runtimeTrainButton:{},trainingRunButton:{},trainingRuntimeStatus:{innerHTML:'',textContent:''}};
  const calls=[];
  const c={document:{getElementById:id=>elements[id]},obj:x=>x||{},esc:x=>String(x??'').replaceAll('<','&lt;'),
    currentDatasetSourceId:'source',currentPreparation:{},runtimeTrainingBusy:false,fullTrainingBusy:false,
    ensureTrainingSource:async()=>{},trainLimit:()=>50000,toast:(...x)=>calls.push(['toast',...x]),
    processSystemDatasetImpl:async()=>({ok:true,data:{preparation_id:'prep'}}),
    submitTrainingJob:async(url,payload)=>{calls.push([url,payload]);return{ok:true,data:{model_version:'new'}}},
    clearAdminCache:()=>{},loadDatasetSourcesData:async()=>{calls.push(['refresh'])},
    loadTrainingRecords:async()=>{},renderTrainingResult:()=>{throw Error('runtime must not touch comparison')},
  };
  vm.createContext(c);
  vm.runInContext(html.slice(html.indexOf('function renderRuntimeTrainingStatus('),html.indexOf('async function runAdminCentralizedTrain(')),c);
  return {c,elements,calls};
}
(async()=>{
  const {c,elements,calls}=setup();
  const state={processed:{dataset_source_id:'source',preparation_id:'prep'},model_inventory:{runtime_detector:{ready:true,version:'old',name:'IF + 逻辑回归',training_context:{preparation_id:'prep'}}}};
  c.renderRuntimeTrainingStatus(state);
  assert(elements.trainingRuntimeStatus.innerHTML.includes('已使用当前准备数据'));
  c.currentDatasetSourceId='another';c.renderRuntimeTrainingStatus(state);
  assert(elements.trainingRuntimeStatus.innerHTML.includes('当前数据尚未用于检测模型'));
  c.currentDatasetSourceId='source';
  const result=await c.runAdminLocalTrain();assert(result.ok);
  const request=calls.find(x=>x[0]==='/api/admin/training/local');
  assert.equal(request[1].expected_preparation_id,'prep');assert.equal(request[1].dataset_source_id,'source');
  assert.equal(elements.runtimeTrainButton.disabled,false);assert.equal(c.runtimeTrainingBusy,false);
  assert(calls.some(x=>x[0]==='refresh'));
  for(const mode of ['changed','failed','throw','busy']){
    const {c,calls,elements}=setup();
    if(mode==='changed')c.processSystemDatasetImpl=async()=>{c.currentDatasetSourceId='changed';return{ok:true,data:{preparation_id:'other'}}};
    if(mode==='failed')c.processSystemDatasetImpl=async()=>({ok:false,error:'no labels'});
    if(mode==='throw')c.submitTrainingJob=async()=>{throw Error('connection lost')};
    if(mode==='busy')c.fullTrainingBusy=true;
    await c.runAdminLocalTrain();
    assert(!calls.some(x=>x[0]==='/api/admin/training/local'));
    assert.equal(c.runtimeTrainingBusy,false);
    if(mode!=='busy')assert.equal(elements.runtimeTrainButton.disabled,false);
  }
  assert(html.includes('三路训练对比 <span class="mini-badge">不替换检测模型'));
  assert(!html.includes('>设为展示版本</button>'));
  console.log('Runtime workflow: pinned preparation, separate serving status, no comparison overwrite, failure cleanup and busy guards passed');
})().catch(e=>{console.error(e);process.exit(1)});
