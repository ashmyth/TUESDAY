'use strict';
/* ==========================================================================
   TUESDAY — Connector adapter index
   Exports the unified Phase-0 connector surface. In a pilot deployment each
   stub is replaced by a real vendor integration — see PRODUCTION_ROADMAP.md
   Phase 1 (weeks 1-2): start with ingestion + firewall block + EDR isolate.
   ========================================================================== */

const ingestion = require('./ingestion');
const containment = require('./containment');
const enrichment = require('./enrichment');

module.exports = { ingestion, containment, enrichment };
