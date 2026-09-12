'use strict';
/* ==========================================================================
   TUESDAY: LLM Runtime (Ollama / OpenAI client)
   Native function-calling. Provides:
   - checkModel()       : connectivity + model availability probe
   - runAgent()         : full ReAct tool-call loop (system + user, max turns)
   - generateJSON()     : single-shot structured JSON output
   All calls timeout + degrade gracefully (return null on failure) so the
   orchestrator can always fall back to the deterministic rule engine.
   ========================================================================== */

const config = require('../config.json');

const OLLAMA_BASE = process.env.OLLAMA_URL || config.ollamaUrl || 'http://localhost:11434';
const MODEL = process.env.TUESDAY_MODEL || config.model;

let dynamicProvider = null;

function setProvider(prov) {
  dynamicProvider = prov;
}

function getProvider() {
  if (dynamicProvider) return dynamicProvider;
  if (process.env.LLM_PROVIDER) return process.env.LLM_PROVIDER;
  if (process.env.VERCEL) return 'gemini';
  return 'ollama';
}

async function checkModel() {
  const provider = getProvider();
  if (provider === 'gemini') {
    const apiKey = process.env.GEMINI_API_KEY;
    const baseUrl = 'https://generativelanguage.googleapis.com/v1beta/openai';
    const model = process.env.GEMINI_MODEL || 'gemini-1.5-flash';

    const hasKey = !!apiKey;
    return { 
      ok: true, 
      base: baseUrl, 
      model, 
      available: [model], 
      present: hasKey, 
      fallbackModel: config.fallbackModel,
      provider: 'gemini'
    };
  }

  try {
    const res = await fetch(`${OLLAMA_BASE}/api/tags`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return { ok: false, error: `ollama http ${res.status}` };
    const data = await res.json();
    const available = (data.models || []).map(m => m.name);
    const present = available.some(m => m === MODEL || m.startsWith(MODEL));
    return { ok: true, base: OLLAMA_BASE, model: MODEL, available, present, fallbackModel: config.fallbackModel, provider: 'ollama' };
  } catch (e) {
    return { ok: false, error: e.message, base: OLLAMA_BASE, model: MODEL, provider: 'ollama' };
  }
}

async function warmModel() {
  const provider = getProvider();
  if (provider === 'gemini') return { ok: true };

  // Pre-load the model into VRAM at boot so the first investigation
  // doesn't stall on a cold model load. Graceful: never throws.
  try {
    const res = await fetch(`${OLLAMA_BASE}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        messages: [{ role: 'user', content: 'ok' }],
        stream: false,
        options: { num_predict: 1, num_ctx: config.numCtx || 8192 }
      }),
      signal: AbortSignal.timeout(60000)
    });
    return { ok: res.ok };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function rawChat({ messages, tools, format, temperature }) {
  const provider = getProvider();

  if (provider === 'gemini') {
    const apiKey = process.env.GEMINI_API_KEY;
    const baseUrl = 'https://generativelanguage.googleapis.com/v1beta/openai';
    const targetModel = process.env.GEMINI_MODEL || 'gemini-1.5-flash';

    if (!apiKey) throw new Error(`GEMINI_API_KEY is not set`);
    
    const body = {
      model: targetModel,
      messages,
      temperature: temperature ?? config.temperature ?? 0.2,
      max_tokens: config.maxTokens || 900,
    };
    if (tools && tools.length) body.tools = tools;
    if (format === 'json') body.response_format = { type: 'json_object' };

    const res = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(config.timeoutMs || 120000)
    });
    
    if (!res.ok) {
        const errText = await res.text();
        throw new Error(`gemini http ${res.status}: ${errText}`);
    }
    const data = await res.json();
    return { message: data.choices[0].message };
  }

  const body = {
    model: MODEL,
    messages,
    stream: false,
    options: { temperature: temperature ?? config.temperature ?? 0.2, num_predict: config.maxTokens || 900, num_ctx: config.numCtx || 8192 }
  };
  if (tools && tools.length) body.tools = tools;
  if (format) body.format = format;

  const res = await fetch(`${OLLAMA_BASE}/api/chat`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(config.timeoutMs || 120000)
  });
  if (!res.ok) throw new Error(`ollama http ${res.status}`);
  return res.json();
}

// --- JSON extraction helpers (local models are sloppy) ---------------------

function extractJSON(text) {
  if (!text) return null;
  const t = text.trim();
  try { return JSON.parse(t); } catch { /* fall through */ }
  const fenced = t.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) { try { return JSON.parse(fenced[1].trim()); } catch { /* */ } }
  const obj = t.match(/\{[\s\S]*\}/);
  if (obj) { try { return JSON.parse(obj[0]); } catch { /* */ } }
  const arr = t.match(/\[[\s\S]*\]/);
  if (arr) { try { return JSON.parse(arr[0]); } catch { /* */ } }
  return null;
}

function safeString(v, max) {
  const s = String(v ?? '').replace(/\s+/g, ' ').trim();
  return s.length > (max || 220) ? s.slice(0, (max || 220)) + '…' : s;
}

function fmtArgs(args) {
  try {
    const parsed = typeof args === 'string' ? JSON.parse(args) : args;
    return Object.entries(parsed).map(([k, v]) => `${k}=${safeString(v, 60)}`).join(', ') || '{}';
  } catch { return safeString(args, 80); }
}

function fmtResult(result) {
  return safeString(JSON.stringify(result), 220);
}

// --- ReAct tool-call loop ---------------------------------------------------

async function runAgent({ agentKey, name, system, user, tools, emitLog, maxTurns }) {
  const messages = [
    { role: 'system', content: system },
    { role: 'user', content: user }
  ];
  const transcript = [];
  let toolCalls = 0;
  const turns = maxTurns || config.maxTurns || 4;

  for (let turn = 0; turn < turns; turn++) {
    const resp = await rawChat({ messages, tools });
    const msg = resp.message || {};
    const content = (msg.content || '').trim();
    const calls = msg.tool_calls || [];

    if (calls.length) {
      messages.push({ role: 'assistant', content: content || null, tool_calls: calls });
      for (const tc of calls) {
        toolCalls++;
        const fnName = tc.function && tc.function.name;
        const fnArgs = (tc.function && tc.function.arguments) || '{}';
        let result;
        try {
          result = await invokeToolSafe(fnName, fnArgs);
        } catch (e) {
          result = { error: e.message };
        }
        if (emitLog) {
          emitLog(agentKey, `TOOL → ${fnName}(${fmtArgs(fnArgs)})`, 'info');
          emitLog(agentKey, `RESULT → ${fmtResult(result)}`, 'info');
        }
        transcript.push({ turn, tool: fnName, args: fnArgs, result });
        
        const toolMsg = { role: 'tool', name: fnName, content: JSON.stringify(result) };
        if (tc.id) toolMsg.tool_call_id = tc.id;
        messages.push(toolMsg);
      }
      continue;
    }

    // No more tool calls — this is the final answer.
    const parsed = extractJSON(content);
    return {
      output: parsed || { verdict: 'INCONCLUSIVE', confidence: 0, reasoning: safeString(content, 400), summary: safeString(content, 120) },
      transcript, toolCalls, content
    };
  }

  return { output: { verdict: 'INCONCLUSIVE', confidence: 0, reasoning: 'Max reasoning turns reached without a final JSON answer.' }, transcript, toolCalls, content: '' };
}

async function generateJSON({ system, user, temperature }) {
  const messages = [
    { role: 'system', content: system },
    { role: 'user', content: user }
  ];
  const resp = await rawChat({ messages, format: 'json', temperature });
  const content = ((resp.message || {}).content || '').trim();
  return extractJSON(content);
}

let toolImplCache = null;
async function invokeToolSafe(name, args) {
  if (!toolImplCache) toolImplCache = require('./tools').TOOL_IMPL;
  const fn = toolImplCache[name];
  if (!fn) return { error: `unknown tool ${name}` };
  let parsed = {};
  if (typeof args === 'string') { try { parsed = JSON.parse(args); } catch { parsed = {}; } }
  else if (args && typeof args === 'object') parsed = args;
  // Models sometimes pass whole alert objects where a primitive is expected —
  // stringify any non-primitive values so tools still see usable text.
  Object.keys(parsed).forEach(k => {
    const v = parsed[k];
    if (v && typeof v === 'object') parsed[k] = JSON.stringify(v);
  });
  return fn(parsed);
}

module.exports = { checkModel, warmModel, runAgent, generateJSON, extractJSON, OLLAMA_BASE, MODEL, getProvider, setProvider };
