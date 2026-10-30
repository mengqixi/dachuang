const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('index.html','utf8');
const extract=(a,b)=>html.slice(html.indexOf(a),html.indexOf(b));
const base=()=>({obj:x=>x||{},arr:x=>Array.isArray(x)?x:[],esc:x=>String(x??'').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),console});
(async()=>{
 const c={...base(),adminCache:new Map(),ADMIN_CACHE_TTL:10000};vm.createContext(c);
 vm.runInContext(extract('function cacheKey(','function previewCols('),c);
 let finishOld,finishNew;
 c.api=()=>new Promise(resolve=>finishOld=resolve);
 const old=c.cachedApi('/test');c.clearAdminCache('/test');
 c.api=()=>new Promise(resolve=>finishNew=resolve);
 const newer=c.cachedApi('/test');finishOld({ok:true,data:'old'});await old;
 finishNew({ok:true,data:'new'});await newer;
 assert.equal((await c.cachedApi('/test')).data,'new');
 const header=c.table([{}],[['<img src=x onerror=alert(1)>','column']]);
 assert(header.includes('&lt;img'));assert(!header.includes('<img'));
 assert(!html.includes('onclick="detectFromSystemDataset()"'));

 const elements={submissionPrevButton:{},submissionNextButton:{},submissionPageInfo:{}};
 const s={...base(),submissionListRequest:0,submissionPageOffset:0,document:{getElementById:id=>elements[id]},
 submissionRiskMetrics:{},submissionTable:{},pageLoaded:new Set(),clearAdminCache(){},toast(){},
 auditPageText:(offset,count,total)=>`${offset}/${count}/${total}`,renderSubmissionRows:rows=>rows.map(x=>x.id).join(','),riskSummaryCounts:()=>({})};
 vm.createContext(s);vm.runInContext(extract('function changeSubmissionPage(','function datasetSourceActions('),s);
 const result=(id,total=45)=>({ok:true,data:{submissions:[{id}],total,summary:{total,high:2,medium:3,trainable:0}}});
 let url;s.cachedApi=async value=>{url=value;return result('first');};
 await s.loadSubmissionsData();assert(url.endsWith('offset=0'));assert.equal(elements.submissionPrevButton.disabled,true);assert.equal(elements.submissionNextButton.disabled,false);
 await s.changeSubmissionPage(1);assert(url.endsWith('offset=20'));assert.equal(elements.submissionPageInfo.textContent,'20/1/45');
 let slow;s.cachedApi=()=>new Promise(r=>slow=r);const before=s.loadSubmissionsData();
 s.cachedApi=async()=>result('current');await s.changeSubmissionPage(1);
 slow(result('stale'));await before;assert.equal(s.submissionTable.innerHTML,'current');
 s.cachedApi=async()=>({ok:false,error:'offline'});await s.loadSubmissionsData();
 assert(s.submissionTable.innerHTML.includes('加载失败'));assert(s.submissionRiskMetrics.innerHTML.includes('--'));
 assert.equal(elements.submissionNextButton.disabled,true);
 s.cachedApi=async()=>({ok:true,data:{submissions:[],total:0,summary:{total:0}}});await s.loadSubmissionsData();assert.equal(s.submissionPageOffset,0);

 const t={...base(),trainingRecordsRequest:0,currentDatasetSourceId:'A',currentPreparation:{preparation_id:'prep'},trainingTable:{},
 trainingResultSummary:{},pageLoaded:new Set(),clearAdminCache(){},renderTrainingCompare(){},
 chartNumber:x=>x===null||x===undefined?null:Number(x),trainingTaskTypeLabel:x=>x,trainingTaskStatusLabel:x=>x,
 trainingMetricInfo:()=>({}),trainingDataNote:()=>'',aggregationSummary:()=>'',fmtTime:x=>x||'-',
 latestTrainingTasks:[],trainingTaskMatchesCurrentPreparation:()=>true,selectTrainingTriplet:()=>({}),trainingComparisonSeries:()=>[],loadSavedTrainingAiComparison:async()=>{},loadModelVersions:async()=>{}};
 vm.createContext(t);vm.runInContext(extract('async function loadTrainingRecords(','function modelTypeLabel('),t);
 t.cachedApi=async()=>({ok:false});assert.equal(await t.loadTrainingRecords(false,false),false);
 assert(t.trainingResultSummary.innerHTML.includes('读取失败'));assert(!t.trainingResultSummary.innerHTML.includes('尚无训练结果'));
 let finish;t.cachedApi=()=>new Promise(r=>finish=r);const training=t.loadTrainingRecords(false,false);t.currentDatasetSourceId='B';
 finish({ok:true,data:{tasks:[]}});await training;assert(t.trainingResultSummary.innerHTML.includes('读取失败'));
 t.cachedApi=async()=>({ok:true,data:{tasks:[],queue:{jobs:[{status:'queued',task_type:'centralized'}]}}});
 await t.loadTrainingRecords(false,false);assert(t.trainingTable.innerHTML.includes('>--</b>'));assert(!t.trainingTable.innerHTML.includes('0.0000'));

 const n={...base(),nodeListRequest:0,currentDatasetSourceId:'A',currentPreparation:{preparation_id:'p'},
 currentDatasetSource:{prepared_for_federated:true},currentRuntimeMatchesPreparation:false,fedNodes:{},fedNodesDataProcess:{},trainNodeMetric:{},
 updateDataProcessReadyState:ready=>n.ready=ready};
 vm.createContext(n);vm.runInContext(extract('function federatedNodeLabel(','function aggregationMethodLabel('),n);
 n.cachedApi=async()=>({ok:true,data:{nodes:[{name:'hospital',samples:40,ready:true}],preparation:{preparation_id:'p',dataset_source_id:'A',preprocessing_version:'v',validation_split_version:'s'}}});
 await n.loadNodes();assert.equal(n.ready,false);assert.notEqual(n.trainNodeMetric.textContent,'4 / 4');
 n.cachedApi=async()=>({ok:false});await n.loadNodes();assert.equal(n.trainNodeMetric.textContent,'读取失败');
 assert(n.fedNodes.innerHTML.includes('读取失败'));
 console.log('Frontend review: escaped headers, cache invalidation, pagination and stale-response guards, explicit failures, queued metrics and real node readiness passed');
})().catch(e=>{console.error(e);process.exitCode=1});
