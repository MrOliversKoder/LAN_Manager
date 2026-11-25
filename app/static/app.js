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
