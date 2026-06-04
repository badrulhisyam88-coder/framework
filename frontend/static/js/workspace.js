/**
 * V1 PR2 — Phase-tabbed workspace: Recon / Enumeration / Exploitation.
 *
 * Recon + Enumeration panes render aggregation cards from workspace-data.json.
 * Exploitation pane mounts a React Flow mind tree (exploit-tree.js).
 * Preact category graph, sidebar category tree, and right panel are preserved.
 *
 *   1. Phase tab switching — shows/hides phase panes, updates URL ?phase=
 *   2. Aggregation cards — rendered from phases[].aggregations into Recon/Enum panes
 *   3. Exploit tree — React Flow tree mounted/refreshed in Exploitation pane
 *   4. Category sub-tabs in Exploitation pane for category filtering
 *   5. Polling (1.1s) — same mechanism as before
 *   6. Capture / context panel — htmx fetch into #ws-panel-body (unchanged)
 */

(function () {
  'use strict';

  // ── State ────────────────────────────────────────────────────────────────

  var _invId        = '';
  var _target       = '';
  var _pollTimer    = null;
  var _openNodeId   = '';
  var _wsActiveSlug = '';   // tracks active category tab slug (for the Preact graph)

  // PR2 additions
  var _activePhase         = 'recon';  // 'recon' | 'enumeration' | 'exploitation'
  var _activeCategorySlug  = '';       // category filter inside exploitation pane
  var _latestData          = null;     // most recent workspace-data.json payload
  var _exploitTreeMounted  = false;    // tracks whether ReactDOM.createRoot was called
  var _showDropped         = false;

  // ── HTML escape helper ────────────────────────────────────────────────────

  function _esc(s) {
    return String(s || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ── Phase switching ───────────────────────────────────────────────────────

  function setActivePhase(phase) {
    _activePhase = phase;

    // Show/hide phase panes
    document.querySelectorAll('.phase-pane').forEach(function (pane) {
      pane.classList.add('hidden');
    });
    var activePaneEl = document.getElementById('phase-pane-' + phase);
    if (activePaneEl) activePaneEl.classList.remove('hidden');

    // Update tab styling
    document.querySelectorAll('.phase-tab').forEach(function (tab) {
      var isActive = tab.dataset.phase === phase;
      tab.classList.toggle('border-[#0969da]', isActive);
      tab.classList.toggle('text-[#0969da]', isActive);
      tab.classList.toggle('font-semibold', isActive);
      tab.classList.toggle('border-transparent', !isActive);
      tab.classList.toggle('text-[#656d76]', !isActive);
    });

    document.querySelectorAll('.phase-sidebar-tab').forEach(function (tab) {
      var isActive = tab.dataset.phase === phase;
      tab.classList.toggle('bg-[#ddf4ff]', isActive);
      tab.classList.toggle('text-[#0969da]', isActive);
      tab.classList.toggle('text-[#656d76]', !isActive);
    });

    // Show/hide category tree in sidebar (only under exploitation)
    var catTree = document.getElementById('category-tree');
    if (catTree) {
      catTree.classList.toggle('hidden', phase !== 'exploitation');
    }

    // Mount/refresh exploit tree when switching to exploitation
    if (phase === 'exploitation' && _latestData) {
      _mountOrRefreshExploitTree(_latestData);
    }

    // Update URL
    try {
      var url = new URL(window.location.href);
      url.searchParams.set('phase', phase);
      history.replaceState(null, '', url.toString());
    } catch (_) {}
  }

  // ── Aggregation card rendering ────────────────────────────────────────────

  function _renderAggregationCards(containerId, aggregations, emptyMsg) {
    var container = document.getElementById(containerId);
    if (!container) return;
    if (!aggregations || !aggregations.length) {
      container.innerHTML = '<div class="text-sm text-[#656d76] py-8 text-center">'
        + _esc(emptyMsg || 'No findings yet') + '</div>';
      return;
    }

    container.innerHTML = aggregations.map(function (agg) {
      var itemsHtml = '';
      if (agg.items && agg.items.length) {
        itemsHtml = '<details class="mt-2"><summary class="text-xs text-[#0969da] cursor-pointer">Show details (' + agg.items.length + ')</summary><div class="mt-2 space-y-1">'
          + agg.items.map(function (item) {
              if (item.signal !== undefined) {
                return '<div class="text-xs text-[#656d76] font-mono bg-[#f6f8fa] rounded px-2 py-1">' + _esc(item.signal) + '</div>';
              }
              if (item.title !== undefined) {
                return '<div class="text-xs"><span class="font-medium">' + _esc(item.title) + '</span><span class="ml-2 text-[#656d76]">' + _esc(item.description || '') + '</span></div>';
              }
              if (item.key !== undefined) {
                return '<div class="text-xs"><span class="text-[#656d76]">' + _esc(item.key) + ':</span> <span class="font-mono">' + _esc(item.value) + '</span></div>';
              }
              return '';
            }).join('')
          + '</div></details>';
      }
      var status = agg.validation_status || 'pending';
      var isDropped = status === 'dropped';
      var badge = '';
      if (status === 'validated') {
        badge = '<span style="background:#dafbe1;color:#1a7f37;font-size:11px;padding:1px 6px;border-radius:10px;margin-left:8px;font-weight:500">Validated</span>';
      } else if (status === 'incomplete') {
        var gapCount = (agg.enumeration_gaps || []).length;
        badge = '<span style="background:#fff8c5;color:#9a6700;font-size:11px;padding:1px 6px;border-radius:10px;margin-left:8px;font-weight:500">Incomplete' + (gapCount ? ': ' + gapCount + ' gap(s)' : '') + '</span>';
      } else if (status === 'dropped') {
        badge = '<span style="background:#f6f8fa;color:#57606a;font-size:11px;padding:1px 6px;border-radius:10px;margin-left:8px;font-weight:500">Dropped</span>';
      }
      var GAP_LABELS = {
        'csrf_token_needed': 'CSRF token required',
        'session_needed': 'Authenticated session required',
        'credentials_needed': 'Valid credentials required',
        'tool_missing': 'Required tool unavailable',
        'exploit_validation_needed': 'Manual exploit validation needed',
      };
      var gapsHtml = '';
      if (status === 'incomplete' && agg.enumeration_gaps && agg.enumeration_gaps.length) {
        gapsHtml = '<ul style="margin:6px 0 0 0;padding-left:16px;font-size:11px;color:#9a6700">'
          + agg.enumeration_gaps.map(function (g) {
              return '<li>' + _esc(GAP_LABELS[g] || g) + '</li>';
            }).join('')
          + '</ul>';
      }
      var cardStyle = isDropped ? 'opacity:0.6;border-style:dashed' : '';
      var droppedLabel = isDropped && agg.validation_reason
        ? '<div style="font-size:11px;color:#57606a;margin-top:4px">Dropped: ' + _esc(agg.validation_reason) + '</div>'
        : '';
      return '<div class="bg-white border border-[#d0d7de] rounded-lg p-4 mb-3" style="' + cardStyle + '">'
        + '<div class="font-medium text-sm text-[#1f2328]">' + _esc(agg.title) + badge + '</div>'
        + (agg.sub_text ? '<div class="text-xs text-[#656d76] mt-1 font-mono">' + _esc(agg.sub_text) + '</div>' : '')
        + droppedLabel
        + gapsHtml
        + itemsHtml
        + '</div>';
    }).join('');
  }

  // ── Exploit category sub-tabs ─────────────────────────────────────────────

  function _renderExploitCategoryTabs(cats) {
    var container = document.getElementById('exploit-cat-tabs');
    if (!container) return;
    var exploitCats = cats || [];
    if (!exploitCats.length) { container.innerHTML = ''; return; }

    container.innerHTML = '<button data-cat="all" class="exploit-cat-tab px-3 py-1.5 text-xs rounded bg-[#f3f4f6] text-[#1f2328] hover:bg-[#e3e8ee]">All</button>'
      + exploitCats.map(function (cat) {
          return '<button data-cat="' + _esc(cat.slug) + '" class="exploit-cat-tab px-3 py-1.5 text-xs rounded bg-[#f3f4f6] text-[#1f2328] hover:bg-[#e3e8ee]">'
            + _esc(cat.label) + '</button>';
        }).join('');

    // Restore active visual state for current category slug.
    var _activeSlug = _activeCategorySlug || 'all';
    container.querySelectorAll('.exploit-cat-tab').forEach(function (b) {
      var isActive = b.dataset.cat === _activeSlug;
      b.classList.toggle('bg-[#0969da]', isActive);
      b.classList.toggle('text-white', isActive);
      b.classList.toggle('bg-[#f3f4f6]', !isActive);
      b.classList.toggle('text-[#1f2328]', !isActive);
    });

    container.querySelectorAll('.exploit-cat-tab').forEach(function (btn) {
      btn.addEventListener('click', function () {
        _activeCategorySlug = btn.dataset.cat;
        container.querySelectorAll('.exploit-cat-tab').forEach(function (b) {
          var active = b.dataset.cat === _activeCategorySlug;
          b.classList.toggle('bg-[#0969da]', active);
          b.classList.toggle('text-white', active);
          b.classList.toggle('bg-[#f3f4f6]', !active);
          b.classList.toggle('text-[#1f2328]', !active);
        });
        if (_latestData) _mountOrRefreshExploitTree(_latestData);
      });
    });
  }

  // ── Phase status badges ───────────────────────────────────────────────

  function _renderPhaseStatus(data) {
    var badges = {
      recon:        { running: data.is_recon_running,       done: !data.is_recon_running && data.current_phase !== 'recon' },
      enumeration:  { running: data.is_enumeration_running, done: !data.is_enumeration_running && (data.current_phase === 'exploitation' || data.current_phase === 'complete') },
      exploitation: { available: data.current_phase === 'exploitation' || data.current_phase === 'complete' },
    };

    document.querySelectorAll('.phase-tab').forEach(function (tab) {
      var phase  = tab.dataset.phase;
      var badge  = badges[phase];
      if (!badge) return;

      // Remove any existing badge span
      var existing = tab.querySelector('.phase-status-badge');
      if (existing) existing.remove();

      var text = '';
      if (phase === 'recon' || phase === 'enumeration') {
        if (badge.running) text = 'Running';
        else if (badge.done) text = 'Complete';
      } else if (phase === 'exploitation') {
        if (!badge.available) text = 'Waiting';
      }

      if (text) {
        var span = document.createElement('span');
        span.className = 'phase-status-badge text-[10px] px-1.5 py-0.5 rounded ml-1 '
          + (badge.running ? 'bg-[#ddf4ff] text-[#0969da]'
             : badge.done ? 'bg-[#dafbe1] text-[#1a7f37]'
             : 'bg-[#f6f8fa] text-[#656d76]');
        span.textContent = text;
        tab.appendChild(span);
      }
    });
  }

  // ── Exploit tree mounting ─────────────────────────────────────────────────

  function _filterTreeByCategory(treeData, categorySlug) {
    var nodes = treeData.nodes || [];
    var edges = treeData.edges || [];

    // Finding nodes carry category_id from the server; match directly.
    var matchedFindingIds = {};
    nodes.forEach(function (n) {
      if (n.data && n.data.kind === 'finding' && n.data.category_id === categorySlug) {
        matchedFindingIds[n.id] = true;
      }
    });

    if (!Object.keys(matchedFindingIds).length) return treeData;

    // Collect action nodes that are children of matched findings.
    var matchedActionIds = {};
    edges.forEach(function (e) {
      if (matchedFindingIds[e.source]) {
        matchedActionIds[e.target] = true;
      }
    });

    var filteredNodes = nodes.filter(function (n) {
      return matchedFindingIds[n.id] || matchedActionIds[n.id];
    });
    var filteredEdges = edges.filter(function (e) {
      return matchedFindingIds[e.source] && matchedActionIds[e.target];
    });

    if (!filteredNodes.length) return treeData;
    return { nodes: filteredNodes, edges: filteredEdges };
  }

  function _mountOrRefreshExploitTree(data) {
    var treeData = data.exploit_tree;
    if (!treeData || !treeData.nodes || !treeData.nodes.length) {
      // Only show the placeholder when the React component has NEVER been mounted.
      // Two-pronged check to catch both direct mountExploitationMindmap calls
      // (which set _roots but not _exploitTreeMounted) and the normal flow:
      //   1. _exploitTreeMounted: set by _mountOrRefreshExploitTree on first mount
      //   2. DOM check: React Flow always renders [class*="react-flow__"] children
      //
      // This is the recurring "canvas disappears on run-start" root cause:
      //   run starts → inv-topology-refresh → workspace-data fetch races →
      //   nodes=[] → root.innerHTML destroys React → canvas blank until tab-switch.
      var _root = document.getElementById('exploit-tree-root');
      var _domMounted = _root && _root.querySelector('[class*="react-flow__"]');
      if (!_exploitTreeMounted && !_domMounted) {
        if (_root) {
          _root.innerHTML = '<div class="text-sm text-[#656d76] py-12 text-center">No exploitation actions available yet — run enumeration probes first</div>';
        }
      }
      // If already mounted (either flag or DOM): leave the React component intact.
      return;
    }
    if (!window.mountExploitationMindmap) return;

    var filteredData = treeData;
    if (_activeCategorySlug && _activeCategorySlug !== 'all') {
      filteredData = _filterTreeByCategory(treeData, _activeCategorySlug);
    }

    if (!_exploitTreeMounted) {
      window.mountExploitationMindmap('exploit-tree-root', filteredData, _invId);
      _exploitTreeMounted = true;
    } else if (window.refreshExploitationMindmap) {
      window.refreshExploitationMindmap('exploit-tree-root', filteredData);
    }
  }

  // ── Tab switching (category tabs for Preact graph) ────────────────────────

  function setActiveTab(slug) {
    if (!slug) return;
    _wsActiveSlug = slug;
    // Propagate to mindmap category filter so URL-restored and poll-restored
    // tab state is honoured without requiring a physical click.
    _activeCategorySlug = slug !== 'all' ? slug : '';

    // Sidebar category button highlighting
    document.querySelectorAll('.cat-tab').forEach(function (tab) {
      var isActive = tab.dataset.tab === slug;
      tab.classList.toggle('bg-[#f3f4f6]', isActive);
      tab.classList.toggle('text-[#1f2328]', isActive);
      tab.classList.toggle('font-medium',    isActive);
    });


    // Persist in URL
    try {
      var url = new URL(window.location.href);
      url.searchParams.set('tab', slug);
      history.replaceState(null, '', url.toString());
    } catch (_) {}
  }

  function _initTabs() {
    document.querySelectorAll('.cat-tab').forEach(function (tab) {
      tab.addEventListener('click', function () {
        _activeCategorySlug = tab.dataset.tab;
        setActiveTab(tab.dataset.tab);
        if (_latestData) _mountOrRefreshExploitTree(_latestData);
      });
    });
  }

  function _initPhaseTabs() {
    // Top phase tabs and sidebar phase tabs
    document.querySelectorAll('.phase-tab, .phase-sidebar-tab').forEach(function (tab) {
      tab.addEventListener('click', function () { setActivePhase(tab.dataset.phase); });
    });
  }

  // ── Capture side panel ───────────────────────────────────────────────────

  function openCapturePanel(bundleId) {
    if (!_invId || !bundleId) return;
    var panel     = document.getElementById('ws-panel');
    var panelBody = document.getElementById('ws-panel-body');
    if (!panel || !panelBody) return;

    panel.classList.remove('hidden');
    panelBody.innerHTML = '<div class="text-[#656d76] text-xs py-4 text-center">Loading…</div>';

    _openNodeId = 'bundle-' + bundleId;
    fetch('/api/v1/validation/workspace/investigations/' + _invId
          + '/context-panel/bundle-' + bundleId)
      .then(function (r) { return r.text(); })
      .then(function (html) {
        panelBody.innerHTML = html;
        if (window.htmx) window.htmx.process(panelBody);
      })
      .catch(function (e) {
        panelBody.innerHTML = '<div class="text-red-400 text-xs py-4 text-center">'
          + 'Failed to load bundle: ' + e.message + '</div>';
      });
  }

  function closePanel() {
    // Panel is persistent — hide only the branch detail card inside Zone C.
    var detail = document.getElementById('ws-branch-detail');
    if (detail) detail.classList.add('hidden');
    _openNodeId = '';
  }

  function openContextPanel(nodeId) {
    if (!_invId || !nodeId) return;
    var detail    = document.getElementById('ws-branch-detail');
    var panelBody = document.getElementById('ws-panel-body');
    if (!detail || !panelBody) return;

    detail.classList.remove('hidden');
    panelBody.innerHTML = '<div class="text-[#656d76] text-xs py-4 text-center">Loading…</div>';

    _openNodeId = nodeId;
    fetch('/api/v1/validation/workspace/investigations/' + _invId
          + '/context-panel/' + nodeId)
      .then(function (r) { return r.text(); })
      .then(function (html) {
        panelBody.innerHTML = html;
        if (window.htmx) window.htmx.process(panelBody);
      })
      .catch(function (e) {
        panelBody.innerHTML = '<div class="text-red-400 text-xs py-4 text-center">'
          + 'Failed to load: ' + e.message + '</div>';
      });
  }

  // Expose for exploit-tree.js
  window.openContextPanel = openContextPanel;

  // ── Panel events ─────────────────────────────────────────────────────────

  function _initPanel() {
    // #ws-panel-close removed — panel is persistent; branch detail close is in Zone C.
    document.addEventListener('htmx:afterRequest', function (evt) {
      if (evt.detail && evt.detail.requestConfig) {
        var method = (evt.detail.requestConfig.verb || '').toUpperCase();
        if (method === 'POST' && _invId) {
          if (_pollTimer) clearTimeout(_pollTimer);
          _pollTimer = setTimeout(_poll, 400);
        }
      }
    });
  }

  // ── Panel refresh ─────────────────────────────────────────────────────────

  function _refreshPanel() {
    if (!_invId || !_openNodeId) return;
    if (window.getSelection && window.getSelection().toString()) return;
    var panelBodyEl = document.getElementById('ws-panel-body');
    if (panelBodyEl) {
      var inputs = panelBodyEl.querySelectorAll('input[type="text"], input:not([type])');
      for (var i = 0; i < inputs.length; i++) {
        if (inputs[i] === document.activeElement) return;
        if (inputs[i].value !== inputs[i].defaultValue) return;
      }
      if (panelBodyEl.querySelector('.space-y-1 details[open]')) return;
    }

    fetch('/api/v1/validation/workspace/investigations/' + _invId
          + '/context-panel/' + _openNodeId)
      .then(function (r) { return r.text(); })
      .then(function (html) {
        var pb = document.getElementById('ws-panel-body');
        if (pb) { pb.innerHTML = html; if (window.htmx) window.htmx.process(pb); }
      })
      .catch(function () {});
  }

  // ── Sidebar rebuild + Preact data push ────────────────────────────────────

  function _treeHasReady(nodes) {
    return nodes.some(function (tn) {
      return tn.card.status === 'ready' || _treeHasReady(tn.children || []);
    });
  }

  function _renderCategories(data) {
    _latestData = data;
    var cats = data.categories || [];

    // Build exploit-node category set once; reused for both sidebar and chips.
    var _exploitNodeCats = {};
    ((data.exploit_tree || {}).nodes || []).forEach(function (n) {
      if (n.data && n.data.kind === 'finding' && n.data.category_id) {
        _exploitNodeCats[n.data.category_id] = true;
      }
    });

    // ── Sidebar category tree ─────────────────────────────────────────────
    var tree = document.getElementById('category-tree');
    if (tree) {
      var tabsHtml = cats.filter(function (c) { return _exploitNodeCats[c.slug]; }).map(function (cat) {
        var capBadge = cat.capture_count > 0
          ? '<span class="text-xs text-[#1a7f37]">' + cat.capture_count
              + ' capture' + (cat.capture_count !== 1 ? 's' : '') + '</span>'
          : '<span class="text-xs text-[#656d76]">' + cat.stage_count + '</span>';

        var bullet = (cat.is_done || cat.capture_count > 0)
          ? '<span class="text-[#1a7f37]">✓</span>'
          : '<span class="text-[#bf8700]">•</span>';

        var alertDot = _treeHasReady(cat.stage_tree || [])
          ? '<span title="Ready action available" style="font-size:9px;line-height:1">🔴</span>'
          : '';

        return '<button data-tab="' + _esc(cat.slug) + '"'
          + ' class="cat-tab w-full flex items-center justify-between pl-12 pr-4 py-2 text-sm text-[#656d76] hover:bg-[#f3f4f6]">'
          + '<span class="flex items-center gap-2">'
          + bullet + '<span>' + _esc(cat.label) + '</span>' + alertDot
          + '</span>'
          + capBadge + '</button>';
      }).join('');
      tree.innerHTML = tabsHtml;
      // Category tree only visible under Exploitation tab
      if (_activePhase === 'exploitation') {
        tree.classList.remove('hidden');
      }
    }

    // Re-attach sidebar category click handlers
    _initTabs();

    // Restore sidebar active-tab CSS
    var urlTab = new URLSearchParams(window.location.search).get('tab');
    var active = urlTab || data.default_tab || (cats[0] && cats[0].slug) || '';
    if (active) setActiveTab(active);

    // Render aggregation cards for Recon + Enumeration panes
    var phases = data.phases || {};
    _renderAggregationCards('recon-agg-cards',
      (phases.recon || {}).aggregations,
      data.is_recon_running ? 'Recon running…' : undefined);
    _renderAggregationCards('enumeration-agg-cards',
      (phases.enumeration || {}).aggregations,
      data.is_enumeration_running
        ? 'Enumeration running…'
        : (data.is_recon_running ? 'Enumeration starts after Recon completes' : undefined));

    // Exploitation category sub-tabs — same filter as sidebar above.
    _renderExploitCategoryTabs(cats.filter(function (c) { return _exploitNodeCats[c.slug]; }));

    // Phase status badges
    _renderPhaseStatus(data);

    // Refresh exploit tree if we're already on exploitation
    if (_activePhase === 'exploitation') {
      _mountOrRefreshExploitTree(data);
    }
  }

  // ── Polling ──────────────────────────────────────────────────────────────

  function _poll() {
    if (!_invId) return;
    var pollUrl = '/api/v1/validation/workspace/investigations/' + _invId + '/workspace-data.json';
    if (_showDropped) pollUrl += '?include_dropped=true';
    fetch(pollUrl)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        _renderCategories(data);
        _refreshPanel();
        var live = data.is_recon_running || data.is_enumeration_running || data.has_active_execution;
        if (live) { _pollTimer = setTimeout(_poll, 1100); } else { _pollTimer = null; }
      })
      .catch(function () { _pollTimer = setTimeout(_poll, 3000); });
  }

  function _startPolling(data) {
    if (_pollTimer) clearTimeout(_pollTimer);
    _pollTimer = null;
    if (data.is_recon_running || data.is_enumeration_running || data.has_active_execution) {
      _pollTimer = setTimeout(_poll, 1100);
    }
  }

  // ── Investigation modal ──────────────────────────────────────────────────

  window.openStartModal = function () {
    var m = document.getElementById('start-modal');
    if (m) m.classList.remove('hidden');
    var inp = document.getElementById('modal-target');
    if (inp) inp.focus();
  };

  window.closeStartModal = function () {
    var m = document.getElementById('start-modal');
    if (m) m.classList.add('hidden');
  };

  window.wsClosePanel = closePanel;

  window.wsToggleDropped = function () {
    _showDropped = !_showDropped;
    var btn = document.getElementById('toggle-dropped-btn');
    if (btn) btn.textContent = _showDropped ? 'Hide filtered findings' : 'Show filtered findings';
    _fetchAndRender();
  };

  function _fetchAndRender() {
    if (!_invId) return;
    var url = '/api/v1/validation/workspace/investigations/' + _invId + '/workspace-data.json';
    if (_showDropped) url += '?include_dropped=true';
    fetch(url)
      .then(function (r) { return r.json(); })
      .then(function (data) { _renderCategories(data); })
      .catch(function () {});
  }

  // ── inv-topology-refresh event ────────────────────────────────────────────
  // Fired by exploit-tree.js after a successful Execute POST.

  window.addEventListener('inv-topology-refresh', function () {
    if (!_invId) return;
    fetch('/api/v1/validation/workspace/investigations/' + _invId + '/workspace-data.json')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        _renderCategories(data);
        _refreshPanel();
      })
      .catch(function () {});
  });

  // ── Init ─────────────────────────────────────────────────────────────────

  function init() {
    var root = document.getElementById('ws-root');
    if (!root) return;

    _invId  = root.dataset.investigationId || '';
    _target = root.dataset.target          || '';

    _initPanel();
    _initPhaseTabs();

    // Read server-embedded initial data
    var initialData = null;
    var dataEl = document.getElementById('ws-initial-data');
    if (dataEl) {
      try { initialData = JSON.parse(dataEl.textContent); } catch (_) {}
    }

    // Resolve initial phase from URL (or server-rendered active_phase)
    var urlPhase = new URLSearchParams(window.location.search).get('phase');
    var serverPhase = (root.dataset.activePhase || 'recon');
    _activePhase = urlPhase || serverPhase || 'recon';

    // Resolve initial category tab
    if (initialData && initialData.categories && initialData.categories.length) {
      var urlTab = new URLSearchParams(window.location.search).get('tab');
      _wsActiveSlug = urlTab
        || initialData.default_tab
        || initialData.categories[0].slug
        || '';
    }

    // Apply phase UI state immediately (before mount so first paint is correct)
    setActivePhase(_activePhase);

    if (initialData) {
      _renderCategories(initialData);
    }
    _poll();

    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closePanel(); });

    // BFCache restore: browser back-button returns the live DOM — hide branch detail
    // so a stale branch from a prior click in the same session doesn't linger on reload.
    window.addEventListener('pageshow', function (evt) {
      if (evt.persisted) {
        var _bd = document.getElementById('ws-branch-detail');
        if (_bd) _bd.classList.add('hidden');
      }
    });

    var modal = document.getElementById('start-modal');
    if (modal) {
      modal.addEventListener('click', function (e) {
        if (e.target === modal) window.closeStartModal();
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
