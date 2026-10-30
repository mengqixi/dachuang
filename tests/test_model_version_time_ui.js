const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('index.html','utf8');
const c={obj:x=>x||{},parseJsonObject:x=>typeof x==='string'?JSON.parse(x):x||{}};
vm.createContext(c);
vm.runInContext(html.slice(html.indexOf('function pad2('),html.indexOf('function isSensitivePreviewKey(')),c);
vm.runInContext(html.slice(html.indexOf('function modelVersionTime('),html.indexOf('function modelSourceLabel(')),c);
for(const value of [
  {timestamp:'2026-10-30T20:38:39.1'},
  {created_at:'2026-10-30 20:38:39'},
  {trained_at:'2026-10-30 20:38:39'},
  {timestamp:'-',metadata:JSON.stringify({timestamp:'2026-10-30 20:38:39'})},
  {metadata:JSON.stringify({metadata:JSON.stringify({created_at:'2026-10-30 20:38:39'})})},
])assert.equal(c.modelVersionTime(value),'2026-10-30 20:38:39');
assert.equal(c.modelVersionTime({version:'fed20261030203839'}),'时间未记录');
assert(html.includes('esc(modelVersionTime(v))'));assert(html.includes('esc(modelVersionTime(raw))'));
console.log('Model version time: top-level, fallback, nested metadata and no inferred timestamps passed');
