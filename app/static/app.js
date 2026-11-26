(function () {
  var csrf = document.body.dataset.csrf;

  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });

  var tt = document.getElementById('theme-toggle');
  if (tt) tt.addEventListener('click', function () {
    var next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('theme', next); } catch (e) {}
  });

  // Management type: show only the matching fields on the service form.
  var mt = document.querySelector('select[name=management_type]');
  if (mt) {
    var sync = function () {
      document.querySelectorAll('[data-mt]').forEach(function (el) {
        el.hidden = el.dataset.mt.split(' ').indexOf(mt.value) < 0;
      });
    };
    mt.addEventListener('change', sync); sync();
  }

  // Clipboard API needs HTTPS; LAN dashboards are usually plain HTTP, so fall back to execCommand.
  function copy(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (ok, fail) {
      var t = document.createElement('textarea');
      t.value = text; t.style.cssText = 'position:fixed;opacity:0';
      document.body.appendChild(t); t.select();
      try { document.execCommand('copy') ? ok() : fail(); } catch (e) { fail(e); }
      t.remove();
    });
  }

  function reveal(id) {
    return fetch('/credentials/' + id + '/reveal', { method: 'POST', headers: { 'X-CSRF': csrf } }).then(function (r) {
      if (r.status === 401) { location.href = '/login'; return null; }
      if (r.status === 403) { location.href = '/credentials/unlock?next=' + encodeURIComponent(location.pathname + location.search); return null; }
      return r.json().then(function (j) { if (!r.ok) { alert(j.error || 'Failed'); return null; } return j.password; });
    });
  }

  function flash(btn, text) {
    var old = btn.textContent; btn.textContent = text;
    setTimeout(function () { btn.textContent = old; }, 1200);
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-act]');
    if (!b) return;
    var row = b.closest('[data-cred]'), act = b.dataset.act, pw = row.querySelector('.pw');
    if (act === 'copy-user') {
      copy(row.dataset.user).then(function () { flash(b, 'Copied'); }, function () { flash(b, 'Failed'); });
    } else if (act === 'copy-pass') {
      reveal(row.dataset.cred).then(function (p) {
        if (p !== null) copy(p).then(function () { flash(b, 'Copied'); }, function () { flash(b, 'Failed'); });
      });
    } else if (act === 'toggle') {
      if (b.textContent === 'Hide') { pw.textContent = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022'; b.textContent = 'Show'; return; }
      reveal(row.dataset.cred).then(function (p) { if (p !== null) { pw.textContent = p || '(empty)'; b.textContent = 'Hide'; } });
    }
  });
})();

// "Test connection": send the current form values, show which methods work, let the user apply one.
(function () {
  var btn = document.getElementById('test-conn');
  if (!btn) return;
  var out = document.getElementById('test-out'), form = btn.closest('form');
  function esc(t) { var d = document.createElement('div'); d.textContent = t == null ? '' : t; return d.innerHTML; }
  btn.addEventListener('click', function () {
    btn.disabled = true; out.hidden = false; out.innerHTML = '<p class="sub">Testing...</p>';
    fetch(btn.dataset.url, { method: 'POST', headers: { 'X-CSRF': document.body.dataset.csrf }, body: new FormData(form) })
      .then(function (r) { if (r.status === 401) { location.href = '/login'; return null; } return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        btn.disabled = false;
        if (!res) return;
        if (!res.ok) { out.innerHTML = '<p class="err">' + esc(res.j.error || 'Test failed') + '</p>'; return; }
        var rows = res.j.results.map(function (r, i) {
          return '<tr><td><span class="dot ' + (r.ok ? 'online' : 'offline') + '"></span> ' + esc(r.label) + '</td><td>' +
            (r.ok ? 'Works' + (r.ms != null ? ' (' + Math.round(r.ms) + ' ms' + (r.code ? ', HTTP ' + r.code : '') + ')' : '') :
              '<span class="sub">' + esc(r.error || 'Failed') + (r.code ? ' (HTTP ' + r.code + ')' : '') + '</span>') + '</td><td>' +
            (r.ok ? '<button type="button" class="btn sm" data-apply="' + i + '">Use this</button>' : '') + '</td></tr>';
        }).join('');
        var rec = res.j.recommended ? '<p>Recommended method: <b>' + esc(res.j.recommended) + '</b></p>' :
          '<p class="err">Nothing answered on ' + esc(res.j.host) + '. Check the address, or the device may be off.</p>';
        out.innerHTML = rec + '<table class="grid">' + rows + '</table>';
        out.querySelectorAll('[data-apply]').forEach(function (b) {
          b.addEventListener('click', function () {
            var a = res.j.results[+b.dataset.apply].apply;
            Object.keys(a).forEach(function (k) { var el = form.elements[k]; if (el) el.value = a[k]; });
            b.textContent = 'Applied';
          });
        });
      }, function () { btn.disabled = false; out.innerHTML = '<p class="err">Test failed. Is the server reachable?</p>'; });
  });
})();
