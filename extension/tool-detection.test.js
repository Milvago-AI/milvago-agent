import test from 'node:test';
import assert from 'node:assert/strict';
import {detectTool} from './policy.js';
const vocabulary=['chrome','edge','firefox','chromium','brave'];
const chromeUA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36';
const brands=(...names)=>({brands:names.map(brand=>({brand,version:'152'}))});
test('the browser is identified by brands and user agent, never by the presence of the browser namespace',()=>{
 // Chrome 152 exposes globalThis.browser exactly like Firefox; the namespace proves nothing,
 // and this is what had Chrome recorded as Firefox in the console.
 assert.equal(detectTool({userAgent:chromeUA,userAgentData:brands('Google Chrome','Chromium','Not A Brand')}),'chrome');
 assert.equal(detectTool({userAgent:chromeUA+' Edg/152.0.0.0',userAgentData:brands('Microsoft Edge','Chromium')}),'edge');
 assert.equal(detectTool({userAgent:chromeUA,userAgentData:brands('Brave','Chromium')}),'brave');
 assert.equal(detectTool({userAgent:chromeUA,userAgentData:brands('Chromium')}),'chromium');
 assert.equal(detectTool({userAgent:'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0'}),'firefox');
 // Brands absent (older Chromium builds): the user agent decides.
 assert.equal(detectTool({userAgent:chromeUA+' Edg/120.0.0.0'}),'edge');
 assert.equal(detectTool({userAgent:chromeUA}),'chromium');
 // Nothing known at all (test runners): a value the agent accepts, never a throw.
 assert.equal(detectTool(undefined),'chrome');
 assert.equal(detectTool({}),'chrome');
 for(const nav of [undefined,{},{userAgent:chromeUA},{userAgentData:brands('Something Else')}]){assert.ok(vocabulary.includes(detectTool(nav)));}
});
