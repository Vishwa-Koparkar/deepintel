const {chromium} = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
(async () => {
 const browser = await chromium.launch({executablePath:process.env.CHROME_PATH || '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser', headless:true});
 try {
  const page = await browser.newPage();
  page.setDefaultTimeout(120000);
  await page.goto('http://127.0.0.1:4180/verify.html');
  await page.addScriptTag({url:'/node_modules/onnxruntime-web/dist/ort.wasm.min.js'});
  await page.addScriptTag({url:'/features.js'});
  const result = await page.evaluate(async () => {
   ort.env.wasm.numThreads=1;
   ort.env.wasm.wasmPaths='/node_modules/onnxruntime-web/dist/';
   const initStart=performance.now();
   const session=await ort.InferenceSession.create('model.onnx',{executionProviders:['wasm']});
   const initMs=performance.now()-initStart;
   const reference=await fetch('reference.json').then(r=>r.json());
   const metadata=await fetch('metadata.json').then(r=>r.json());
   let featureMismatches=0;
   const browserFeatures=reference.urls.map((url,row)=>{
    const features=DeepIntelFeatures.extractFeatures(DeepIntelFeatures.normalizeForAnalysis(url),metadata.featureConfig);
    return metadata.features.map((key,col)=>{const value=Math.fround(features[key]);if(value!==reference.features[row][col])featureMismatches++;return value;});
   });
   const input=new ort.Tensor('float32',Float32Array.from(browserFeatures.flat()),[browserFeatures.length,20]);
   const start=performance.now();
   const output=await session.run({[session.inputNames[0]]:input});
   const inferenceMs=performance.now()-start;
   const one=new ort.Tensor('float32',Float32Array.from(browserFeatures[0]),[1,20]);
   const singleTimes=[];
   for(let i=0;i<30;i++){const begin=performance.now();await session.run({[session.inputNames[0]]:one});singleTimes.push(performance.now()-begin);}
   singleTimes.sort((a,b)=>a-b);

   const probabilities=output[session.outputNames[1]].data;
   let maxError=0,labelChanges=0;
   for(let row=0;row<reference.features.length;row++) {
    let predicted=0;
    for(let cls=0;cls<3;cls++) {
     const p=probabilities[row*3+cls];
     maxError=Math.max(maxError,Math.abs(p-reference.probabilities[row][cls]));
     if(p>probabilities[row*3+predicted])predicted=cls;
    }
    if(predicted!==reference.labels[row])labelChanges++;
   }
   return {runtime:'onnxruntime-web WASM', rows:reference.features.length,featureValues:reference.features.length*20,featureMismatches,maxProbabilityError:maxError,labelChanges,initMs,inferenceMs,warmSingleMedianMs:singleTimes[15],warmSingleP95Ms:singleTimes[28],perRowBatchMs:inferenceMs/reference.features.length};
  });
  assert.equal(result.featureMismatches,0);
  assert.equal(result.labelChanges,0);
  assert.ok(result.maxProbabilityError<1e-5,JSON.stringify(result));
  fs.writeFileSync(path.join(__dirname,'browser-results.json'),JSON.stringify(result,null,2)+'\n');
  console.log(JSON.stringify(result,null,2));
 } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
