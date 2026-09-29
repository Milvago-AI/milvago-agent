import test from 'node:test';
import assert from 'node:assert/strict';
import {platformBlockRules, blockedPlatform, blockedTab, keptWhenSealed} from './model-rules.js';
import {networkRules} from './policy.js';

test('Community ignores platform blocks even when a policy supplies them', () => {
  const policy={version:3,revision:4,expires_at:'2099-01-01T00:00:00Z',config:{services:[],collection:{enabled:true},blocked_platforms:[
    {id:'dedicated',domains:['ai.example.invalid']},
    {id:'shared',domains:['tools.example.invalid'],paths:['/assistant*']},
  ]}};
  assert.deepEqual(platformBlockRules(policy),[]);
  assert.equal(blockedPlatform(policy,'dedicated'),false);
  assert.equal(blockedTab(policy,'https://ai.example.invalid/chat'),false);
  assert.equal(blockedTab(policy,'https://tools.example.invalid/assistant/chat'),false);
  assert.deepEqual(networkRules(policy),[]);
  assert.equal(keptWhenSealed({id:40000,action:{type:'block'},condition:{requestDomains:['ai.example.invalid']}}),false);
});
