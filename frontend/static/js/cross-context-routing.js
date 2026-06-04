/**
 * cross-context-routing.js
 *
 * Single source of truth for all navigation from ai-assist-tool
 * into AI_Cyber_Lab. The backend knows nothing about this URL.
 *
 * ── Configuration ───────────────────────────────────────────────
 * Set CYBERLAB_URL below, or override it before this script loads:
 *
 *   <script>window.CYBERLAB_URL = 'https://your-cyberlab.example.com';</script>
 *   <script src="/static/js/cross-context-routing.js"></script>
 *
 * In a Vite/React project this would be injected as VITE_CYBERLAB_URL
 * from .env.local. This project uses a static-template stack, so the
 * value lives here. See frontend/.env.local for the config reference.
 * ────────────────────────────────────────────────────────────────
 */

(function () {
  'use strict';

  // ── URL config (edit this or override via window.CYBERLAB_URL) ─────────────
  var CYBERLAB_URL = window.CYBERLAB_URL || 'http://localhost:3000';

  // ── Internal URL builders ──────────────────────────────────────────────────

  function _findingsUrl(type, severity) {
    var p = new URLSearchParams({ source: 'ai-assist' });
    if (type)     p.set('type', type);
    if (severity) p.set('severity', severity);
    return CYBERLAB_URL + '/findings?' + p.toString();
  }

  function _open(url) {
    window.open(url, '_blank', 'noopener,noreferrer');
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Sidebar nav "Learning Workspace" — opens the general findings workspace.
   */
  window.openCyberLabLearning = function () {
    _open(CYBERLAB_URL + '/findings?source=ai-assist');
  };

  /**
   * Finding detail page "Learn in CyberLab".
   * @param {HTMLElement} el  Button element with data-type and data-severity.
   */
  window.openCyberLabFinding = function (el) {
    var type     = el.dataset.type     || '';
    var severity = el.dataset.severity || '';
    _open(_findingsUrl(type, severity));
  };

  /**
   * Investigation workspace "Open in CyberLab".
   * @param {HTMLElement} el  Button element with data-type and data-severity.
   */
  window.openCyberLabWorkspace = function (el) {
    var type     = el.dataset.type     || '';
    var severity = el.dataset.severity || '';
    _open(_findingsUrl(type, severity));
  };

})();
