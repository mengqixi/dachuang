const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('index.html','utf8');
const extract=(a,b)=>html.slice(html.indexOf(a),html.indexOf(b));
const c={obj:x=>x||{},arr:x=>Array.isArray(x)?x:[],esc:x=>String(x??'').replaceAll('<','&lt;'),
 parseJsonObject:x=>typeof x==='string'?JSON.parse(x):x||{},trainingMetricInfo:()=>({}),
 infoButton:()=>'<button>说明</button>',chartNumber:x=>x===null||x===undefined||x===''?null:Number(x)};
vm.createContext(c);
vm.runInContext(extract('function trainingMetricsComparable(','function trainingValidationInfo('),c);
vm.runInContext(extract('function trainingRecordToCompare(','function trainingTaskMatchesCurrentPreparation('),c);
vm.runInContext(extract('function trainingComparisonSeries(','function showTrainingDetails('),c);
const shared={comparison_run_id:'run-1',validation_id:'v',metric_scope:'shared_holdout_validation',base_model_algorithm:'linear',optimizer:'batch',epochs:20,samples:160,accuracy:.8,recall:.7,f1:.75};
const record=(kind,version,run='run-1')=>({task_type:kind==='local'?'centralized':'federated',status:'completed',metadata:JSON.stringify({...shared,comparison_run_id:run,model_version:version,aggregation_method:kind==='secure'?'fedavg_paillier_secure':'plain',paillier:kind==='secure'?{secure_aggregation:true,actual_crypto_operations_performed:true}:{} })});
const records=[record('secure','s1'),record('federated','f1'),record('local','c1')];
c.trainingCompareState=c.selectTrainingTriplet(records);
assert.equal(c.trainingCompareState.local.version,'c1');assert.equal(c.trainingCompareState.federated.version,'f1');assert.equal(c.trainingCompareState.secure.version,'s1');
assert(c.trainingTripletComparable());
const quality=c.trainingTripletVisual('quality');
assert(quality.includes('普通集中式'));assert(quality.includes('普通 FedAvg'));assert(quality.includes('Paillier FedAvg'));
assert.equal((quality.match(/class="paired-bar-line"/g)||[]).length,9);
assert(c.trainingTripletVisual('speed').includes('未记录'));
// Latest incomplete run must not borrow the previous run's successful secure model.
c.trainingCompareState=c.selectTrainingTriplet([record('federated','f2','run-2'),record('local','c2','run-2'),...records]);
assert.equal(c.trainingCompareState.secure,null);assert(!c.trainingTripletComparable());
assert(c.trainingTripletVisual().includes('尚未完整匹配'));
const bad=record('secure','fake');bad.metadata=JSON.stringify({...JSON.parse(bad.metadata),paillier:{secure_aggregation:true,display_only:true}});
assert.equal(c.trainingRecordVariant(bad),null);
assert(!html.includes('id="federatedAggregationMode"'));
assert(html.includes("submitTrainingJob('/api/admin/training/comparison'"));
console.log('Three-way UI: independent variants, nine bars, exact run restore, incomplete/error states and no fake secure record passed');
