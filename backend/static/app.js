// app.js - moved inline JS from index.html (focused, Py/HTML-independent)
// Responsibilities:
// - global fetch wrapper (credentials: 'include', Authorization from localStorage)
// - login/logout handlers (cookie cleared by server; token kept in localStorage for header transport)
// - results panel state machine (idle/loading/success/empty/error) with Spanish messages
// - render: desktop table + mobile cards, radicado single-line + tooltip, Guardar button responsiveness
// - small helpers: escapeHtml, normalizaFecha, normalizaRowParaTabla
// Note: UI versioning and cache-busting are handled by index.html referencing /static/app.js?v={{UI_VERSION}}

(function () {
  'use strict';

  // State machine messages (Spanish)
  const STATE_MESSAGES = {
    idle: "Aún no has realizado una consulta. Ingresa uno o varios radicados y presiona ‘Consultar Procesos’.",
    loading: "Cargando resultados...",
    empty: "No se encontraron resultados.",
    error: "Ocurrió un error al consultar. Inténtalo de nuevo."
  };

  // Auth token stored here for header-based transport (cookie transport still used via credentials: 'include')
  let authToken = localStorage.getItem('authToken') || null;
  let currentUser = null;

  // Override window.fetch to ensure credentials included and Authorization header if local token present
  (function(){
    if (typeof window === 'undefined') return;
    const origFetch = window.fetch.bind(window);
    window.fetch = function(resource, init = {}) {
      // ensure credentials include cookies
      if (!init.credentials) init.credentials = 'include';
      // ensure headers object
      init.headers = init.headers || {};
      // If no Authorization header present, and we have a token in localStorage, add it
      const headerKeys = Object.keys(init.headers || {});
      const hasAuthHeader = headerKeys.some(k => String(k).toLowerCase() === 'authorization');
      const token = localStorage.getItem('authToken');
      if (!hasAuthHeader && token) {
        init.headers['Authorization'] = `Bearer ${token}`;
      }
      return origFetch(resource, init);
    };
  })();

  // Lightweight fetchJSON helper that returns { ok, status, json }
  async function fetchJSON(url, opts = {}) {
    opts.credentials = opts.credentials || 'include';
    opts.headers = opts.headers || {};
    const token = localStorage.getItem('authToken');
    if (!opts.headers['Authorization'] && token) opts.headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(url, opts);
    let body = null;
    const text = await res.text().catch(() => null);
    try {
      body = text ? JSON.parse(text) : null;
    } catch (e) {
      body = text;
    }
    return { ok: res.ok, status: res.status, body, rawText: text };
  }

  // DOM references
  const queryResultEl = () => document.getElementById('query-result');
  const batchNumbersEl = () => document.getElementById('batch-numbers');
  const btnBatchQuery = () => document.getElementById('btn-batch-query');
  const loginForm = () => document.getElementById('login-form');
  const loginScreen = () => document.getElementById('login-screen');
  const appScreen = () => document.getElementById('app-screen');
  const logoutBtn = () => document.getElementById('logout-btn');
  const userEmailSpan = () => document.getElementById('user-email');

  // Initialize UI on load
  function init() {
    // wire main buttons
    const btn = btnBatchQuery();
    if (btn) btn.addEventListener('click', onBatchQueryClick);
    const lf = loginForm();
    if (lf) lf.addEventListener('submit', onLoginFormSubmit);
    const lb = logoutBtn();
    if (lb) lb.addEventListener('click', onLogoutClick);

    // show idle message initially in results panel
    displayIdle();

    // if token present, try to show app and load user info
    if (authToken) {
      showApp();
      loadUserInfo().catch(() => { /* ignore */ });
    } else {
      showAuth();
    }

    // sync table/cards on resize
    window.addEventListener('resize', debounce(syncTableToCards, 120));
    // also run once
    setTimeout(syncTableToCards, 200);
  }

  // UI helpers
  function showAuth() {
    if (loginScreen()) loginScreen().classList.remove('hidden');
    if (appScreen()) appScreen().classList.add('hidden');
  }
  function showApp() {
    if (loginScreen()) loginScreen().classList.add('hidden');
    if (appScreen()) appScreen().classList.remove('hidden');
  }

  async function onLoginFormSubmit(ev) {
    ev.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    if (!email || !password) {
      toastError('Por favor completa todos los campos');
      return;
    }
    await login(email, password);
  }

  async function onLogoutClick(ev) {
    ev.preventDefault();
    await logout();
  }

  async function login(email, password) {
    try {
      const r = await fetchJSON('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      if (r.ok && r.body && r.body.access_token) {
        authToken = String(r.body.access_token);
        localStorage.setItem('authToken', authToken);
        showApp();
        await loadUserInfo();
        toastSuccess('Sesión iniciada');
      } else {
        const msg = (r.body && r.body.detail) ? r.body.detail : 'Error en el inicio de sesión';
        toastError(msg);
      }
    } catch (e) {
      toastError('Error de conexión');
      console.error('login error', e);
    }
  }

  async function logout() {
    try {
      await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    } catch (e) {
      console.warn('logout request failed', e);
    }
    authToken = null;
    localStorage.removeItem('authToken');
    currentUser = null;
    const uel = userEmailSpan();
    if (uel) uel.textContent = '';
    showAuth();
    toastSuccess('Sesión cerrada');
  }

  async function loadUserInfo() {
    if (!authToken) return;
    try {
      const r = await fetchJSON('/auth/me', { headers: { 'Authorization': `Bearer ${authToken}` } });
      if (r.ok && r.body && r.body.email) {
        currentUser = r.body;
        const uel = userEmailSpan();
        if (uel) uel.textContent = ` ${currentUser.email}`;
        // set avatar initials if present
        const avatar = document.getElementById('avatar');
        if (avatar) {
          const initials = (currentUser.email || 'U').split('@')[0].slice(0,2).toUpperCase();
          avatar.textContent = initials;
        }
      } else {
        // Token invalid; force logout
        await logout();
      }
    } catch (e) {
      console.error('loadUserInfo error', e);
    }
  }

  // Results state transitions
  function displayIdle() {
    const container = queryResultEl();
    if (!container) return;
    container.innerHTML = `<div class="table-empty">${STATE_MESSAGES.idle}</div>`;
  }
  function displayLoading() {
    const container = queryResultEl();
    if (!container) return;
    container.innerHTML = `<div class="table-loading">${STATE_MESSAGES.loading}</div>`;
  }
  function displayEmpty() {
    const container = queryResultEl();
    if (!container) return;
    container.innerHTML = `<div class="table-empty">${STATE_MESSAGES.empty}</div>`;
  }
  function displayError(text) {
    const container = queryResultEl();
    if (!container) return;
    container.innerHTML = `<div class="table-error">${STATE_MESSAGES.error}${text ? ' — ' + escapeHtml(text) : ''}</div>`;
  }

  // Main batch query action
  async function onBatchQueryClick() {
    await batchQuery();
  }

  async function batchQuery() {
    const raw = (batchNumbersEl() && batchNumbersEl().value) ? batchNumbersEl().value.trim() : '';
    if (!raw) { toastError('Por favor ingresa al menos un número de radicación'); return; }
    const numbers = raw.split(',').map(s => s.trim()).filter(Boolean);
    if (numbers.length > 10) { toastError('Máximo 10 procesos por consulta'); return; }

    // basic validation
    const validNumbers = numbers.filter(n => n.length === 23 && /^\d+$/.test(n));
    if (validNumbers.length === 0) {
      // still proceed with original numbers if any (server may respond)
    }

    displayLoading();

    try {
      const q = numbers.join(',');
      const r = await fetchJSON(`/api/procesos?q=${encodeURIComponent(q)}`, { method: 'GET' });
      if (!r.ok) {
        displayError(`Error ${r.status}`);
        return;
      }
      const payload = r.body;
      if (!payload || !Array.isArray(payload.rows)) {
        displayError('Respuesta inesperada del servidor.');
        return;
      }
      const rows = payload.rows.map(normalizaRowParaTabla);
      if (rows.length === 0) {
        displayEmpty();
        return;
      }
      displayResults(rows);
    } catch (e) {
      console.error('batchQuery error', e);
      displayError();
    }
  }

  // Display results (table + cards)
  function displayResults(rows) {
    // store for pagination/filtering if needed
    window.__expedita_results = rows.slice(0);
    // Render table for desktop and card list for mobile
    renderResultsTable(rows);
    syncTableToCards();
  }

  // Minimal renderResultsTable (keeps accessibility & truncation)
  function renderResultsTable(results) {
    const container = queryResultEl();
    if (!container) return;

    if (!results || results.length === 0) {
      displayEmpty();
      return;
    }

    // Build a compact table (columns same as original)
    const tableHtml = `
      <div class="table-wrap results-full">
        <div id="results-wrapper" class="overflow-x-auto -mx-2 lg:mx-0 rounded-xl border border-white/5 bg-neutral-900/40 results-full">
          <table id="results-table" class="results-table w-full min-w-[900px] lg:min-w-0" role="table" aria-label="Resultados">
            <thead>
              <tr>
                <th class="px-3 py-2 text-left">Radicado</th>
                <th class="px-3 py-2 text-left">Demandante</th>
                <th class="px-3 py-2 text-left">Demandado</th>
                <th class="px-3 py-2 text-left">Juzgado</th>
                <th class="px-3 py-2 text-left">Última actuación</th>
                <th class="px-3 py-2 text-right">Guardar</th>
              </tr>
            </thead>
            <tbody id="results-tbody">
            </tbody>
          </table>
        </div>
        <div id="results-cards" class="results-cards hidden" aria-live="polite"></div>
      </div>
    `;
    container.innerHTML = tableHtml;

    const tbody = document.getElementById('results-tbody');
    results.forEach(proc => {
      const rad = escapeHtml(proc.radicado || '');
      const demandante = escapeHtml(proc.demandante || '');
      const demandado = escapeHtml(proc.demandado || '');
      const juzgado = escapeHtml(proc.juzgado || '');
      const fecha = escapeHtml(normalizaFecha(proc.fechaUltimaActuacion));
      const encoded = encodeURIComponent(JSON.stringify(proc));

      const tr = document.createElement('tr');
      tr.className = 'border-b';
      tr.innerHTML = `
        <th class="px-3 py-2 nowrap-token ellipsis font-medium" scope="row" title="${rad}">${rad}</th>
        <td class="px-3 py-2 truncate sm-truncate" title="${demandante}">${demandante}</td>
        <td class="px-3 py-2 truncate sm-truncate" title="${demandado}">${demandado}</td>
        <td class="px-3 py-2 nowrap-token sm-truncate" title="${juzgado}">${juzgado}</td>
        <td class="px-3 py-2">${fecha}</td>
        <td class="px-3 py-2 text-right">
          <button aria-label="Guardar" class="btn-guardar inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-primary" data-proc='${encoded}' onclick="(function(el){ window.__expedita_saveProcess && window.__expedita_saveProcess(el); })(this);">
            <span class="material-icons text-sm icon" aria-hidden="true">bookmark_add</span>
            <span class="label hidden md:inline">Guardar</span>
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    // expose saveProcess handler for inline onclick usage above
    window.__expedita_saveProcess = function(btn) {
      try {
        const procString = btn.getAttribute('data-proc');
        saveProcess(btn, procString);
      } catch (e) { console.error(e); }
    };

    // create cards for mobile
    renderCards(results);
  }

  function renderCards(results) {
    const cardsEl = document.getElementById('results-cards') || null;
    if (!cardsEl) return;
    const items = results.map(proc => {
      const rad = escapeHtml(proc.radicado || '');
      const dem = escapeHtml(proc.demandante || '');
      const ded = escapeHtml(proc.demandado || '');
      const juz = escapeHtml(proc.juzgado || '');
      const fecha = escapeHtml(normalizaFecha(proc.fechaUltimaActuacion));
      const encoded = encodeURIComponent(JSON.stringify(proc));

      return `
        <article class="result-card" role="article" aria-labelledby="radicado-${rad}">
          <div class="top">
            <div class="radicado nowrap-token ellipsis" id="radicado-${rad}" title="${rad}">${rad}</div>
            <div>
              <button aria-label="Guardar" class="btn-guardar inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-primary" data-proc='${encoded}' onclick="(function(el){ window.__expedita_saveProcess && window.__expedita_saveProcess(el); })(this);">
                <span class="material-icons text-sm icon" aria-hidden="true">bookmark_add</span>
                <span class="label hidden md:inline">Guardar</span>
              </button>
            </div>
          </div>
          <div class="field"><div class="label">Demandante</div><div class="value">${dem}</div></div>
          <div class="field"><div class="label">Demandado</div><div class="value">${ded}</div></div>
          <div class="field"><div class="label">Juzgado</div><div class="value nowrap-token">${juz}</div></div>
          <div class="field"><div class="label">Última actuación</div><div class="value">${fecha}</div></div>
        </article>
      `;
    }).join('');
    cardsEl.innerHTML = items;
  }

  // Toggle table/cards visibility based on viewport width
  function syncTableToCards() {
    const cards = document.getElementById('results-cards');
    const wrapper = document.getElementById('results-wrapper');
    if (!cards || !wrapper) return;
    const isMobile = window.innerWidth <= 767;
    if (isMobile) {
      wrapper.style.display = 'none';
      cards.classList.remove('hidden');
    } else {
      wrapper.style.display = 'block';
      cards.classList.add('hidden');
    }
  }

  // Save process stub (calls /api/saved); keeps behavior minimal but functional
  async function saveProcess(btn, procString) {
    if (!procString) return;
    if (!authToken) {
      toastError('Debes iniciar sesión para guardar procesos.');
      showAuth();
      return;
    }
    let proc;
    try { proc = JSON.parse(decodeURIComponent(procString)); } catch (e) { proc = {}; }
    const payload = {
      radicado: proc.radicado || '',
      id_proceso: proc.idProceso || '',
      fecha_ultima_actuacion: proc.fechaUltimaActuacion || null,
      despacho: proc.juzgado || proc.despacho || '',
      demandante: proc.demandante || '',
      demandado: proc.demandado || '',
      response_json: proc._raw ? proc._raw.consulta || null : null,
      detalle_json: proc._raw ? proc._raw.detalle || null : null,
      tipo_proceso: proc.clase || '',
      clase_proceso: proc.clase || '',
      subclase_proceso: proc.subclase || '',
      ubicacion: proc.ubicacion || ''
    };
    try {
      const r = await fetchJSON('/api/saved', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      if (r.ok && r.body && r.body.status === 'OK') {
        toastSuccess('Expediente guardado');
      } else {
        const m = (r.body && r.body.detail) ? r.body.detail : 'Error guardando';
        toastError(m);
      }
    } catch (e) {
      console.error('saveProcess error', e);
      toastError('Error de conexión al guardar');
    }
  }

  // Utilities
  function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function normalizaFecha(value) {
    if (!value) return 'N/A';
    const s = String(value).trim();
    if (/^\d{2}\/\d{2}\/\d{4}$/.test(s)) return s;
    const iso = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (iso) return `${iso[3]}/${iso[2]}/${iso[1]}`;
    try {
      const d = new Date(s);
      if (isNaN(d.getTime())) return 'N/A';
      const dd = String(d.getDate()).padStart(2,'0');
      const mm = String(d.getMonth()+1).padStart(2,'0');
      const yyyy = d.getFullYear();
      return `${dd}/${mm}/${yyyy}`;
    } catch (e) { return 'N/A'; }
  }

  function normalizaRowParaTabla(row) {
    return {
      radicado: row.radicado || row.numero || '',
      idProceso: row.idProceso || row.id_proceso || '',
      demandante: row.demandante || '',
      demandado: row.demandado || '',
      juzgado: row.juzgado || row.despacho || '',
      clase: row.clase || row.clase_proceso || '',
      subclase: row.subclase || row.subclase_proceso || '',
      ubicacion: row.ubicacion || '',
      fechaUltimaActuacion: row.fechaUltimaActuacion || null,
      status: row.status || '',
      error: row.error || '',
      _raw: row._raw || null
    };
  }

  // Simple toast utilities (small, in-page)
  function toastSuccess(msg){ toastShow(msg, 'success'); }
  function toastError(msg){ toastShow(msg, 'error'); }
  function toastShow(msg, type = 'info'){
    try {
      let container = document.getElementById('toast-container');
      if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'fixed top-4 right-4 z-50 space-y-2';
        document.body.appendChild(container);
      }
      const el = document.createElement('div');
      el.className = `p-3 rounded-md text-white ${type==='success'?'bg-green-600':type==='error'?'bg-red-600':'bg-blue-600'}`;
      el.setAttribute('role','alert');
      el.textContent = msg;
      container.appendChild(el);
      setTimeout(()=> { el.style.opacity = '0'; setTimeout(()=>el.remove(),300); }, 3000);
    } catch(e) { console.warn('toast error', e); }
  }

  // Small debounce
  function debounce(fn, wait) {
    let t = null;
    return function() {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, arguments), wait);
    };
  }

  // Kick off
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();