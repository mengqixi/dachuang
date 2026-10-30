const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('index.html','utf8');
const source=html.slice(html.indexOf('let reportDownloadBusy='),html.indexOf('function renderDistTags('));
function setup(){
 const button={textContent:'下载完整报告（PDF）'},downloads=[],errors=[];
 const c={obj:x=>x||{},currentSubmissionId:'submission-A',userResultRevision:0,currentReportPayload:null,
 currentAnalysis:{analysis_trace:{analysis_id:'ana-A'}},document:{getElementById:()=>button,createElement:()=>({click(){downloads.push(this.download)}})},
 URL:{createObjectURL:()=> 'blob:unit',revokeObjectURL(){}},Blob,AbortController,
 setTimeout:(fn,ms)=>ms===90000?setTimeout(fn,ms):0,clearTimeout,
 toast:m=>errors.push(m),fetch:async()=>({ok:true,blob:async()=>new Blob(['%PDF-1.7\nunit'])})};
 vm.createContext(c);vm.runInContext(source,c);return {c,button,downloads,errors};
}
(async()=>{
 let {c,button,downloads}=setup();let calls=0;
 c.fetch=async(url,options)=>{calls++;assert(url.endsWith('/download?analysis_id=ana-A'));assert.equal(options.credentials,'same-origin');return{ok:true,blob:async()=>new Blob(['%PDF-1.7\nunit'])}};
 await c.downloadReport();assert.equal(calls,1);assert.equal(downloads[0],'risk-report-submission-A.pdf');assert.equal(button.disabled,false);
 for(const bad of ['<!DOCTYPE html>','not a PDF']){
   const x=setup();x.c.fetch=async()=>({ok:true,blob:async()=>new Blob([bad])});await x.c.downloadReport();
   assert.equal(x.downloads.length,0);assert(x.errors[0].includes('不是有效 PDF'));assert.equal(x.button.disabled,false);
 }
 const failure=setup();failure.c.fetch=async()=>({ok:false,json:async()=>({msg:'报告不存在'})});await failure.c.downloadReport();
 assert.equal(failure.downloads.length,0);assert.equal(failure.errors[0],'报告不存在');
 const race=setup();let resolve;race.c.fetch=()=>new Promise(r=>resolve=r);
 const task=race.c.downloadReport();await race.c.downloadReport();
 race.c.currentSubmissionId='submission-B';race.c.userResultRevision++;
 resolve({ok:true,blob:async()=>new Blob(['%PDF-1.7'])});await task;
 assert.equal(race.downloads.length,0);assert.equal(race.button.disabled,false);
 console.log('Report download: real PDF, safe filename, ownership credentials, errors, duplicate-click and stale-result guards passed');
})().catch(e=>{console.error(e);process.exitCode=1});
