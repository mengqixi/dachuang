const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('index.html','utf8');
const extract=(a,b)=>html.slice(html.indexOf(a),html.indexOf(b));
const c={obj:x=>x||{},arr:x=>Array.isArray(x)?x:[],esc:x=>String(x??'').replaceAll('<','&lt;'),
 parseJsonObject:x=>typeof x==='string'?JSON.parse(x):x||{},trainingMetricInfo:()=>({}),
 infoButton:()=>'<button>说明</button>',chartNumber:x=>x===null||x===undefined||x===''?null:Number.isFinite(Number(x))?Number(x):null};
vm.createContext(c);
vm.runInContext(extract('function trainingMetricsComparable(','function trainingPerformanceVisual('),c);
vm.runInContext(extract('function trainingRecordToCompare(','function trainingTaskMatchesCurrentPreparation('),c);
vm.runInContext(extract('function trainingComparisonSeries(','function showTrainingDetails('),c);
const shared={dataset_source_id:'s',dataset_revision:'revision',preparation_id:'prep',validation_id:'val',federated_split_version:'split',
 metric_scope:'shared_holdout_validation',base_model_algorithm:'linear',optimizer:'batch',epochs:20,samples:160,validation_samples:40,
 class_weights:{0:.8,1:1.2},accuracy:.8,recall:.7,f1:.75,validation_label_distribution:{0:20,1:20},confusion_matrix:{tn:18,tp:14,fp:2,fn:6},
 performance:{training_time_ms:100,model_compute_time_ms:30,key_setup_time_ms:0,aggregation_time_ms:10}};
const record=(kind,run='run1',change={})=>({task_type:kind==='local'?'centralized':'federated',status:'completed',metadata:JSON.stringify({...shared,
 comparison_run_id:run,model_version:kind+run,aggregation_method:kind==='secure'?'fedavg_paillier_secure':'plain',
 paillier:kind==='secure'?{secure_aggregation:true,actual_crypto_operations_performed:true,encryption_time_ms:30,aggregation_time_ms:10,decryption_time_ms:20,ciphertext_payload_bytes:38912}:{},...change})});
const group=run=>['secure','federated','local'].map(k=>record(k,run));
c.trainingCompareState=c.selectTrainingTriplet(group('run1'));
const errors=c.trainingTripletVisual('errors');
assert.equal((errors.match(/>2 条</g)||[]).length,3);assert.equal((errors.match(/>6 条</g)||[]).length,3);
assert(errors.includes('三路错误数量一致'));assert.equal((errors.match(/class="paired-bar-line"/g)||[]).length,0);
const unequal={...c.trainingCompareState,local:{...c.trainingCompareState.local,confusion_matrix:{tn:17,tp:14,fp:3,fn:6}}};
assert.equal((c.trainingTripletVisual('errors',unequal).match(/class="paired-bar-line"/g)||[]).length,6);
assert.equal(c.trainingConfusion({...c.trainingCompareState.local,validation_samples:41}),null);
assert.equal(c.trainingConfusion({...c.trainingCompareState.local,confusion_matrix:{tn:18,tp:14,fp:-2,fn:10}}),null);
assert.equal(c.trainingConfusion({...c.trainingCompareState.local,confusion_matrix:null}),null);
assert(c.trainingErrorVisual({}).includes('未记录'));
const cost=c.trainingCostParts(c.trainingCompareState.secure);
assert.deepEqual(Array.from(cost.values),[30,0,30,10,20,10]); // outer aggregation=10 is NOT added again.
assert.equal(cost.values.reduce((a,b)=>a+b,0),100);
assert.equal(c.trainingCostParts({...c.trainingCompareState.secure,performance:{...shared.performance,training_time_ms:50}}),null);
assert.equal(c.trainingCostParts({}),null);
assert(c.trainingCostVisual().includes('38.00 KiB'));assert(c.trainingCostVisual().includes('（估算）'));
assert(c.trainingTripletVisual('speed').includes('训练成本分解'));
const headline=c.trainingHeadline();assert(headline.includes('本轮差异'));assert(headline.includes('100.000 ms'));
assert(headline.includes('明文权重聚合'));assert(headline.includes('密文权重聚合'));assert(headline.includes('集中训练'));
assert(!headline.includes('87.50%'));
assert(c.trainingRecordToCompare({accuracy:0,metadata:{accuracy:1}}).accuracy===0);
assert.equal(c.trainingRecordToCompare({metadata:{}}).accuracy,null);
assert.equal(c.trainingRecordToCompare({metadata:{}}).loss,null);
assert.equal(c.trainingStabilityRuns(group('run1')).length,1);
assert.equal(c.trainingStabilityRuns([...group('run1'),...group('run2')]).length,2);
assert.equal(c.trainingStabilityRuns([...group('run1'),...group('run2'),...group('run2')]).length,2);
assert.equal(c.trainingStabilityRuns([...group('run1'),record('local','incomplete'),record('secure','incomplete')]).length,1);
for(const change of [{dataset_revision:'other'},{epochs:10},{validation_id:'other'},{class_weights:{0:1,1:1}},{continued_from_previous_round:true}]){
 const mixed=['secure','federated','local'].map(k=>record(k,'other',change));
 assert.equal(c.trainingStabilityRuns([...group('run1'),...mixed]).length,1);
}
assert(c.trainingStabilityHtml(group('run1')).includes('至少需要 2 组'));
assert(c.trainingStabilityHtml([...group('run1'),...group('run2')]).includes('80.00% ± 0.00 个百分点'));
console.log('Comparison dimensions: actual error counts, missing history, non-overlapping costs, estimated payload and strict repeated-run cohorts passed');
