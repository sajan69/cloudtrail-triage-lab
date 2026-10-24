const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawn, spawnSync} = require('node:child_process');
const {once} = require('node:events');
const {chromium} = require('playwright');

const python = process.env.TRIAGE_PYTHON || 'python';
const root = fs.mkdtempSync(path.join(os.tmpdir(),'triage-browser-'));
const db = path.join(root,'events.duckdb');
const screenshot = process.env.TRIAGE_SCREENSHOT || path.resolve('artifacts/dashboard.png');
let child, browser;
function command(args) { const r=spawnSync(python,['-m','cloudtrail_triage.cli',...args],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);return JSON.parse(r.stdout); }
function start() { return new Promise((resolve,reject)=>{
  child=spawn(python,['-m','cloudtrail_triage.cli','serve','--db',db,'--port','0'],{stdio:['ignore','pipe','pipe']});
  let output='';const timer=setTimeout(()=>reject(new Error('Dashboard startup timed out')),10000);
  child.stdout.on('data',chunk=>{output+=chunk;const match=output.match(/http:\/\/127\.0\.0\.1:\d+\/#[A-Za-z0-9_-]+/);if(match){clearTimeout(timer);resolve(match[0]);}});
  child.on('error',error=>{clearTimeout(timer);reject(error);});
  child.once('exit',code=>{clearTimeout(timer);if(!output.includes('Open http:'))reject(new Error('Dashboard exited before startup: '+code));});
}); }
async function stop(){if(child&&child.exitCode===null){const exited=once(child,'exit');child.kill('SIGTERM');await exited;}}
async function loaded(page){await page.locator('#status').filter({hasText:'Local data loaded'}).waitFor();assert.equal(await page.locator('#error').isVisible(),false);}

(async()=>{
  command(['generate','--out',path.join(root,'fixture')]);
  command(['ingest',path.join(root,'fixture/events.json'),'--db',db]);
  let url=await start();
  browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_EXECUTABLE?{executablePath:process.env.CHROMIUM_EXECUTABLE,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']}: {})});
  const context=await browser.newContext({viewport:{width:1365,height:1000},acceptDownloads:true});
  const page=await context.newPage();const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.goto(url);await loaded(page);
  assert.equal(await page.locator('#event-count').textContent(),'132');
  assert.equal(await page.locator('.finding').count(),5);
  await page.getByRole('button',{name:/CT003 · high priority/}).click();
  await page.locator('#evidence-page').filter({hasText:'1–2 of 2'}).waitFor();
  const downloadPromise=page.waitForEvent('download');
  await page.getByRole('button',{name:'Evidence JSON',exact:true}).click();
  const download=await downloadPromise;const downloaded=path.join(root,'evidence.json');await download.saveAs(downloaded);
  assert.equal(JSON.parse(fs.readFileSync(downloaded,'utf8')).total,2);
  await page.selectOption('#region','us-west-2');await page.selectOption('#source','bedrock.amazonaws.com');
  await page.getByRole('button',{name:'Apply filters',exact:true}).click();await loaded(page);
  await page.locator('#page').filter({hasText:'1–2 of 2'}).waitFor();
  await page.selectOption('#rule','CT002');await page.getByRole('button',{name:'Apply filters',exact:true}).click();
  await page.waitForFunction(()=>document.getElementById('finding-count').textContent==='2');
  await page.locator('#principal').fill("' OR 1=1 --");await page.getByRole('button',{name:'Apply filters',exact:true}).click();
  await page.locator('#page').filter({hasText:'0 matching events'}).waitFor();
  await page.getByRole('button',{name:'Reset',exact:true}).click();await page.waitForFunction(()=>document.getElementById('finding-count').textContent==='5');
  await page.getByRole('button',{name:/CT003 · high priority/}).click();await page.locator('#evidence-page').filter({hasText:'1–2 of 2'}).waitFor();
  fs.mkdirSync(path.dirname(screenshot),{recursive:true});await page.screenshot({path:screenshot,fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'Mobile page should not overflow horizontally');
  await stop();
  const payload='<img src=x onerror="window.triageInjected=true">';
  const adversarial={Records:[{eventID:'00000000-0000-4000-8000-000000009999',eventTime:'2026-01-01T00:00:00Z',eventSource:'ec2.amazonaws.com',eventName:payload,awsRegion:'us-east-1',recipientAccountId:'111122223333',userIdentity:{type:'IAMUser',arn:'arn:aws:iam::111122223333:user/synthetic-browser-check'}}]};
  fs.writeFileSync(path.join(root,'adversarial.json'),JSON.stringify(adversarial));command(['ingest',path.join(root,'adversarial.json'),'--db',db]);
  url=await start();await page.goto(url);await loaded(page);
  assert.ok((await page.locator('#timeline').textContent()).includes(payload));
  assert.equal(await page.locator('#timeline img').count(),0);assert.equal(await page.evaluate(()=>window.triageInjected),undefined);
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({passed:true,checks:['load','select evidence','JSON download','filters','literal SQL input','reset','mobile layout','inert HTML payload'],screenshotCaptured:true}));
})().catch(async error=>{console.error(error.stack);if(browser){const page=browser.contexts()[0]?.pages()[0];if(page)console.error(await page.locator('#status,#error,#finding-count,#rule,#principal').allTextContents());}process.exitCode=1;}).finally(async()=>{if(browser)await browser.close();await stop();fs.rmSync(root,{recursive:true,force:true});});
