// Dependency-free regression checks against the actual inline UI functions.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const html = fs.readFileSync('index.html', 'utf8');
const functions = html.slice(html.indexOf('function datasetSourceCategoryKey('), html.indexOf('function datasetDisplayName('));
const controls = {};
const document = {getElementById: id => controls[id] ||= {innerHTML:'',textContent:'',hidden:false}};
const build = new Function('document', `
  const obj=x=>x||{}, arr=x=>Array.isArray(x)?x:[], esc=x=>String(x??'');
  const datasetDisplayName=s=>s.name||s.id,shortText=(s,n)=>String(s).slice(0,n);
  const sortDatasetSourcesForDisplay=s=>s.slice();
  const renderDistTags=()=>'',distributionScopeNote=()=>'';
  let datasetSourceCategory='all',datasetSourcesExpanded=false,datasetSourceList=[];
  let currentDatasetSourceId='selected',currentDatasetSource={id:'selected',samples:63999,prepared_for_federated:true};
  let compactDatasetRows=[],datasetSourceContext={};
  const selectedUserSources=new Set();
  const datasetSourceTable=document.getElementById('table'),systemDataMetrics=document.getElementById('metrics');
  const datasetSourceActions=s=>'detail-index:'+compactDatasetRows.indexOf(s);
  ${functions}
  return {category:datasetSourceCategoryKey,label:datasetSourceCategoryLabel,counts:datasetPreparationCounts,
    set:setDatasetSourceCategory,render:renderDatasetSourceList,summary:renderDatasetPreparationSummary,select:setUserSourceSelected,
    initialize:list=>{datasetSourceList=list;renderDatasetSourceList()},
    state:()=>({selected:currentDatasetSourceId,rows:compactDatasetRows,table:datasetSourceTable.innerHTML,metrics:systemDataMetrics.innerHTML})};
`);
const ui = build(document);
const sources=[
  {id:'selected',source_type:'CSE-CIC-IDS2018',samples:63999},
  {id:'pool',source_type:'user_submission_pool',samples:200,trainable:true},
  {id:'submission:a',source_type:'user_submission',samples:200,trainable:true},
  {id:'generated',source_type:'local_generated',samples:8000},
  {id:'other',source_type:'custom',samples:2},
];
assert.deepEqual(sources.map(ui.category),['public','user','user','system','other']);
assert(ui.label(sources[1]).includes('汇总数据池'));
assert(ui.label(sources[2]).includes('单份提交'));
ui.initialize(sources);
ui.set('user');
assert.deepEqual(ui.state().rows.map(x=>x.id),['pool','submission:a']);
assert(ui.state().table.includes('detail-index:1'));
assert.equal(ui.state().selected,'selected');
ui.set('system');assert.equal(ui.state().rows.length,1);
ui.set('unknown');assert.equal(ui.state().rows[0].id,'generated');
ui.initialize([]);ui.set('user');assert(ui.state().table.includes('此分类暂无数据源'));
const source={id:'selected',samples:63999,prepared_for_federated:true};
const prep={dataset_source_id:'selected',samples:50000,training_samples:40000,validation_samples:10000};
assert.deepEqual(ui.counts(source,prep),{raw:63999,prepared:50000,train:40000,validation:10000,matches:true});
assert.equal(ui.counts({...source,id:'different'},prep).prepared,'--');
assert.equal(ui.counts({...source,prepared_for_federated:false},prep).prepared,'--');
assert.equal(ui.counts(source,{...prep,validation_samples:0}).validation,0);
ui.summary({processed:prep,model_inventory:{runtime_detector:{ready:true,version:'model-old',training_context:{preparation_id:'old'}}}});
assert(controls.datasetModelStatus.innerHTML.includes('未对应当前准备版本'));
assert(ui.state().metrics.includes('40,000'));
ui.initialize([{id:'submission:a',source_type:'user_submission',submission_id:'a',name:'first.csv',upload_time:'2026-10-30 09:00:00',samples:20,trainable:true},{id:'submission:b',source_type:'user_submission',submission_id:'b',name:'second.csv',samples:30,trainable:true}]);
ui.set('user');assert(ui.state().table.includes('提交 2026-10-30 09:00:00'));
ui.select(0,true);ui.select(1,true);assert.equal(controls.prepareSelectedSourcesButton.disabled,false);
assert.equal(ui.state().selected,'selected');
console.log('Dataset categories, independent selection, detail indices, empty states, preparation counts and model context: passed');
