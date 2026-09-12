'use strict';

/**
 * ============================================================================
 * PROJECT TUESDAY — TACTICAL EDGE INCIDENT RESPONSE CLUSTER
 * Module: Deterministic Telemetry Aggregator & Node B Direct Dispatcher
 * Node A (192.168.0.1) -> Node B (192.168.0.2:11434 / fallback 127.0.0.1)
 * ============================================================================
 */

const http = require('http');

// Cluster Configuration with environment fallback for single-laptop development
const NODE_B_CONFIG = {
  host: process.env.NODE_B_HOST || '192.168.0.2',
  port: parseInt(process.env.NODE_B_PORT || '11434', 10),
  timeoutMs: 12000,
  model: process.env.NODE_B_MODEL || 'phi3.5:3.8b-mini-instruct-q4_K_M'
};

class TelemetryAggregator {
  /**
   * @param {Object} options
   * @param {number} options.windowMs Sliding temporal batch window (default: 1500ms)
   * @param {number} options.maxBatchSize Max alerts before forced immediate flush
   * @param {Function} options.onIncidentReady Callback receiving aggregated incident payload
   */
  constructor(options = {}) {
    this.windowMs = options.windowMs || 1500;
    this.maxBatchSize = options.maxBatchSize || 10;
    this.onIncidentReady = options.onIncidentReady || null;

    this.buffer = [];
    this.timer = null;
    this.batchSequence = 0;
  }

  /**
   * Ingest a single raw alert into the temporal aggregation window
   * @param {Object} alert
   */
  ingest(alert) {
    if (!alert || typeof alert !== 'object') return;

    this.buffer.push({
      ...alert,
      _receivedAt: Date.now()
    });

    // Forced threshold flush if a surge hits max capacity
    if (this.buffer.length >= this.maxBatchSize) {
      this.flush();
      return;
    }

    // Reset or start the sliding window timer
    if (!this.timer) {
      this.timer = setTimeout(() => this.flush(), this.windowMs);
    }
  }

  /**
   * Flushes the buffer and synthesizes a single, dense JSON incident narrative
   */
  flush() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (this.buffer.length === 0) return;

    const rawBatch = this.buffer.splice(0, this.buffer.length);
    const incidentPayload = this._synthesizeBatch(rawBatch);

    if (typeof this.onIncidentReady === 'function') {
      this.onIncidentReady(incidentPayload);
    }
  }

  /**
   * Internal correlation logic: Deduplicates IOCs, groups affected entities,
   * collapses duplicate MITRE TTPs, and builds a consolidated timeline.
   * @private
   */
  _synthesizeBatch(batch) {
    this.batchSequence++;
    const incidentId = `INC-${Date.now().toString(36).toUpperCase()}-${this.batchSequence}`;

    const hosts = new Set();
    const pids = new Set();
    const iocs = new Set();
    const ttps = new Set();
    const sources = new Set();
    const rawEvents = [];

    let maxReportedSeverity = 'LOW';
    const severityWeights = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

    for (const item of batch) {
      if (item.targetHost) hosts.add(item.targetHost);
      if (item.source) sources.add(item.source);

      // Extract and normalize IOCs
      if (item.ioc) {
        const cleanIoc = item.ioc.split(' ')[0].trim();
        if (cleanIoc && cleanIoc !== '127.0.0.1' && cleanIoc !== 'localhost') {
          iocs.add(cleanIoc);
        }
      }

      // Extract PIDs from payload or explicit fields
      if (item.pid) {
        pids.add(String(item.pid));
      } else if (item.payload && typeof item.payload === 'string') {
        const match = item.payload.match(/PID\s+(\d+)/i);
        if (match) pids.add(match[1]);
      }

      // Extract TTPs
      if (item.mitreTtp) ttps.add(item.mitreTtp);
      if (Array.isArray(item.ttps)) item.ttps.forEach(t => ttps.add(t));

      // Calculate aggregated severity ceiling
      const s = (item.severity || 'LOW').toUpperCase();
      if ((severityWeights[s] || 0) > (severityWeights[maxReportedSeverity] || 0)) {
        maxReportedSeverity = s;
      }

      rawEvents.push({
        alertId: item.id || `ALERT-${Math.random().toString(36).substring(2, 7)}`,
        title: item.title || 'Generic Alert',
        timestamp: item.timestamp || new Date(item._receivedAt).toISOString(),
        payload: item.payload || ''
      });
    }

    return {
      incidentId,
      windowStart: new Date(batch[0]._receivedAt).toISOString(),
      windowEnd: new Date(batch[batch.length - 1]._receivedAt).toISOString(),
      alertCount: batch.length,
      severityBaseline: maxReportedSeverity,
      affectedHosts: Array.from(hosts),
      activePIDs: Array.from(pids),
      indicators: Array.from(iocs),
      correlatedTTPs: Array.from(ttps),
      telemetrySources: Array.from(sources),
      events: rawEvents
    };
  }
}

/**
 * Low-latency direct HTTP call to Ollama (/api/generate)
 * Eliminates all framework abstractions (LangChain/CrewAI).
 *
 * @param {string} prompt Formatted input prompt
 * @param {Object} options Optional overrides (temperature, schema enforcement)
 * @returns {Promise<Object>} Direct JSON-parsed model output
 */
function queryNodeB(prompt, options = {}) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: options.model || NODE_B_CONFIG.model,
      prompt: prompt,
      stream: false,
      format: options.format || 'json',
      options: {
        temperature: options.temperature !== undefined ? options.temperature : 0.1,
        num_predict: options.maxTokens || 512
      }
    });

    const targetHost = options.host || NODE_B_CONFIG.host;
    const targetPort = options.port || NODE_B_CONFIG.port;

    const reqOptions = {
      hostname: targetHost,
      port: targetPort,
      path: '/api/generate',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      },
      timeout: options.timeoutMs || NODE_B_CONFIG.timeoutMs
    };

    const startTime = Date.now();

    const req = http.request(reqOptions, (res) => {
      let data = '';

      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        const latencyMs = Date.now() - startTime;
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error(`Ollama returned HTTP ${res.statusCode}: ${data}`));
        }

        try {
          const parsedOllama = JSON.parse(data);
          let responseContent = parsedOllama.response;

          if (options.format === 'json' && typeof responseContent === 'string') {
            responseContent = JSON.parse(responseContent);
          }

          resolve({
            ok: true,
            latencyMs,
            evalCount: parsedOllama.eval_count,
            evalDurationMs: Math.round((parsedOllama.eval_duration || 0) / 1e6),
            result: responseContent
          });
        } catch (err) {
          reject(new Error(`Failed to parse Ollama response: ${err.message}. Raw: ${data}`));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Connection to ${targetHost}:${targetPort} timed out after ${reqOptions.timeout}ms`));
    });

    req.on('error', (err) => {
      reject(new Error(`Cannot connect to Ollama at ${targetHost}:${targetPort} — ${err.message}`));
    });

    req.write(payload);
    req.end();
  });
}

module.exports = {
  TelemetryAggregator,
  queryNodeB,
  NODE_B_CONFIG
};
