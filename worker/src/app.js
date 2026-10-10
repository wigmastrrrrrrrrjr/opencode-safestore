/* opencode-safestore dashboard SPA. No build step, no dependencies. */
(function () {
  "use strict";

  var enc = new TextEncoder();
  var dec = new TextDecoder();
  var ACCT_SALT = enc.encode("safestore:account:v1");
  var STORE_SALT = enc.encode("opencode-safestore/v1");

  var boot = {};
  try { boot = JSON.parse(document.getElementById("boot").textContent || "{}"); } catch (e) { boot = {}; }

  function b64(bytes) {
    var s = "", c = 0x8000;
    for (var i = 0; i < bytes.length; i += c) s += String.fromCharCode.apply(null, bytes.subarray(i, i + c));
    return btoa(s);
  }
  function unb64(value) {
    var bin = atob(value), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    var d = 0;
    for (var i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }
  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  /* ------------------------------- crypto ------------------------------- */
  async function pbkdf2Master(password, saltBytes, iterations) {
    var base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: iterations }, base, 256);
  }
  async function accountKeys(masterBits) {
    var hkdf = await crypto.subtle.importKey("raw", masterBits, "HKDF", false, ["deriveBits"]);
    async function d(info) {
      return crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: ACCT_SALT, info: enc.encode(info) }, hkdf, 256);
    }
    var auth = new Uint8Array(await d("auth"));
    var wrapRaw = await d("wrap");
    var wrap = await crypto.subtle.importKey("raw", wrapRaw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    return { authKey: b64(auth), wrap: wrap };
  }
  async function aesWrap(wrap, keyBytes) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, wrap, keyBytes));
    return JSON.stringify({ iv: b64(iv), ct: b64(ct) });
  }
  async function aesUnwrap(wrap, envelope) {
    var parsed = typeof envelope === "string" ? JSON.parse(envelope) : envelope;
    var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(parsed.iv) }, wrap, unb64(parsed.ct));
    return new Uint8Array(pt);
  }
  async function storeKeys(masterBytes) {
    var base = await crypto.subtle.importKey("raw", masterBytes, "HKDF", false, ["deriveBits"]);
    async function d(info) {
      return crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: STORE_SALT, info: enc.encode(info) }, base, 256);
    }
    var pair = await Promise.all([d("enc"), d("mac")]);
    return {
      enc: await crypto.subtle.importKey("raw", pair[0], { name: "AES-GCM" }, false, ["decrypt"]),
      mac: await crypto.subtle.importKey("raw", pair[1], { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    };
  }
  async function decryptRecord(keys, rec) {
    try {
      var pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(rec.nonce) }, keys.enc, unb64(rec.ciphertext)));
      var mac = new Uint8Array(await crypto.subtle.sign("HMAC", keys.mac, pt));
      if (!bytesEqual(mac, unb64(rec.mac))) return undefined;
      return JSON.parse(dec.decode(pt));
    } catch (e) { return undefined; }
  }
  async function genEcdh() { return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]); }
  async function importSpki(value) { return crypto.subtle.importKey("spki", unb64(value), { name: "ECDH", namedCurve: "P-256" }, true, []); }
  async function exportSpki(key) { return b64(new Uint8Array(await crypto.subtle.exportKey("spki", key))); }
  async function wrapForCli(cliPubB64, keyBytes) {
    var eph = await genEcdh();
    var cliPub = await importSpki(cliPubB64);
    var shared = await crypto.subtle.deriveBits({ name: "ECDH", public: cliPub }, eph.privateKey, 256);
    var hk = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    var aesBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: enc.encode("safestore:cli"), info: enc.encode("key-wrap") }, hk, 256);
    var aes = await crypto.subtle.importKey("raw", aesBits, { name: "AES-GCM" }, false, ["encrypt"]);
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aes, keyBytes));
    return JSON.stringify({ eph_pub: await exportSpki(eph.publicKey), iv: b64(iv), ct: b64(ct) });
  }

  /* ------------------------------ key cache ----------------------------- */
  function saveKey(bytes) { try { sessionStorage.setItem("sf_key", b64(bytes)); } catch (e) {} }
  function cachedKey() { try { var v = sessionStorage.getItem("sf_key"); return v ? unb64(v) : null; } catch (e) { return null; } }
  function saveEmail(email) { try { sessionStorage.setItem("sf_email", email); } catch (e) {} }

  /* -------------------------------- api --------------------------------- */
  async function api(path, options) {
    options = options || {};
    var res = await fetch(path, {
      method: options.method || "GET",
      credentials: "same-origin",
      headers: options.body ? { "content-type": "application/json" } : {},
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    var data = {};
    try { data = await res.json(); } catch (e) {}
    if (!res.ok) { var err = new Error(data.error || ("HTTP " + res.status)); err.status = res.status; throw err; }
    return data;
  }

  /* ------------------------------- chrome ------------------------------- */
  var splash = document.getElementById("splash");
  var splashBar = document.getElementById("splash-bar");
  var splashText = document.querySelector(".splash-text");
  function showSplash(text) { splash.hidden = false; if (text) splashText.textContent = text; setProgress(8); }
  function hideSplash() { splash.hidden = true; }
  function setProgress(pct) { if (splashBar) splashBar.style.width = Math.max(8, Math.min(100, pct)) + "%"; }
  function toast(message, bad) {
    var el = document.createElement("div");
    el.className = "toast" + (bad ? " bad" : "");
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(function () { el.remove(); }, 4200);
  }
  function root() { return document.getElementById("root"); }

  function field(label, id, type, placeholder, autocomplete) {
    return '<label for="' + id + '">' + esc(label) + "</label>" +
      '<input id="' + id + '" type="' + (type || "text") + '" placeholder="' + esc(placeholder || "") + '"' +
      (autocomplete ? ' autocomplete="' + autocomplete + '"' : "") + ">";
  }

  /* ------------------------------- signup ------------------------------- */
  function renderSignup() {
    var next = boot.next || "/app";
    root().innerHTML =
      '<div class="center"><div class="card auth-card fade">' +
      '<div class="brand" style="margin-bottom:18px"><span class="brand-dot"></span> safestore</div>' +
      "<h1>Create your account</h1>" +
      '<p class="sub">Your keys are generated on this device. The server only ever sees them wrapped by your password.</p>' +
      '<form id="form">' + field("Email", "email", "email", "you@example.com", "email") +
      field("Password", "password", "password", "at least 10 characters", "new-password") +
      field("Confirm password", "confirm", "password", "", "new-password") +
      '<div id="err"></div>' +
      '<div style="margin-top:18px"><button class="primary" id="submit" type="submit" style="width:100%">Create account &amp; sign in</button></div>' +
      "</form>" +
      '<p class="small muted" style="margin-top:16px">Already have an account? <a href="/login' +
      (next && next !== "/app" ? "?next=" + encodeURIComponent(next) : "") + '">Sign in</a></p>' +
      "</div></div>";

    document.getElementById("form").addEventListener("submit", async function (event) {
      event.preventDefault();
      var errBox = document.getElementById("err");
      errBox.innerHTML = "";
      var email = document.getElementById("email").value.trim().toLowerCase();
      var password = document.getElementById("password").value;
      var confirm = document.getElementById("confirm").value;
      var btn = document.getElementById("submit");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return (errBox.innerHTML = '<div class="err">Enter a valid email.</div>');
      if (password.length < 10) return (errBox.innerHTML = '<div class="err">Use at least 10 characters.</div>');
      if (password !== confirm) return (errBox.innerHTML = '<div class="err">Passwords do not match.</div>');
      btn.disabled = true; btn.textContent = "Generating keys…";
      try {
        var saltBytes = crypto.getRandomValues(new Uint8Array(16));
        var masterBits = await pbkdf2Master(password, saltBytes, 300000);
        var keys = await accountKeys(masterBits);
        var storeKey = crypto.getRandomValues(new Uint8Array(32));
        var wrapped = await aesWrap(keys.wrap, storeKey);
        btn.textContent = "Creating account…";
        var out = await api("/api/auth/signup", { method: "POST", body: { email: email, salt: b64(saltBytes), authKey: keys.authKey, wrappedKey: wrapped } });
        saveKey(storeKey); saveEmail(email);
        if (out.defaultToken) { try { sessionStorage.setItem("sf_default_token", out.defaultToken); } catch (e) {} }
        location.href = next;
      } catch (error) {
        errBox.innerHTML = '<div class="err">' + esc(error.message) + "</div>";
        btn.disabled = false; btn.textContent = "Create account & sign in";
      }
    });
  }

  /* -------------------------------- login ------------------------------- */
  function renderLogin() {
    var next = boot.next || "/app";
    root().innerHTML =
      '<div class="center"><div class="card auth-card fade">' +
      '<div class="brand" style="margin-bottom:18px"><span class="brand-dot"></span> safestore</div>' +
      "<h1>Sign in</h1>" +
      '<p class="sub">Unlock your encrypted memory. Your password never leaves this device.</p>' +
      '<form id="form">' + field("Email", "email", "email", "you@example.com", "email") +
      field("Password", "password", "password", "", "current-password") +
      '<div id="err"></div>' +
      '<div style="margin-top:18px"><button class="primary" id="submit" type="submit" style="width:100%">Sign in</button></div>' +
      "</form>" +
      '<p class="small muted" style="margin-top:16px">No account? <a href="/signup' +
      (next && next !== "/app" ? "?next=" + encodeURIComponent(next) : "") + '">Create one</a></p>' +
      "</div></div>";

    document.getElementById("form").addEventListener("submit", async function (event) {
      event.preventDefault();
      var errBox = document.getElementById("err");
      errBox.innerHTML = "";
      var email = document.getElementById("email").value.trim().toLowerCase();
      var password = document.getElementById("password").value;
      var btn = document.getElementById("submit");
      btn.disabled = true; btn.textContent = "Unlocking…";
      try {
        var saltRes = await api("/api/auth/salt?email=" + encodeURIComponent(email));
        var masterBits = await pbkdf2Master(password, unb64(saltRes.salt), 300000);
        var keys = await accountKeys(masterBits);
        var out = await api("/api/auth/login", { method: "POST", body: { email: email, authKey: keys.authKey } });
        var storeKey = await aesUnwrap(keys.wrap, out.wrappedKey);
        saveKey(storeKey); saveEmail(email);
        location.href = next;
      } catch (error) {
        errBox.innerHTML = '<div class="err">' + esc(error.status === 401 ? "Invalid email or password." : error.message) + "</div>";
        btn.disabled = false; btn.textContent = "Sign in";
      }
    });
  }

  /* ------------------------------ consent ------------------------------- */
  function scopeText(scopes) {
    var names = { "store:read": "Read every memory session", "store:write": "Create, update and delete memory sessions" };
    return scopes.map(function (s) { return names[s] || s; });
  }
  function renderConsent() {
    var c = boot.consent || {};
    var user = boot.user || {};
    var list = scopeText(c.scopes || []);
    root().innerHTML =
      '<div class="center"><div class="card auth-card fade">' +
      '<div class="brand" style="margin-bottom:18px"><span class="brand-dot"></span> safestore</div>' +
      "<h1>Authorize " + esc(c.appName) + "</h1>" +
      '<p class="sub">Signed in as ' + esc(user.email || "your account") + "</p>" +
      '<div class="warn-title" style="font-weight:600;margin:14px 0 6px">Are you sure you want to log into ' + esc(c.appName) + "?</div>" +
      "<p class=\"small muted\">It is requesting access to:</p>" +
      list.map(function (t) { return '<div class="consent-scope">' + esc(t) + "</div>"; }).join("") +
      '<p class="small muted" style="margin-top:12px">This could be dangerous — it can use all your sessions.</p>' +
      '<div id="err"></div>' +
      '<div class="row" style="margin-top:18px"><button class="ghost" id="deny">Cancel</button><span class="spacer"></span>' +
      '<button class="primary" id="approve">Continue</button></div>' +
      "</div></div>";

    document.getElementById("deny").addEventListener("click", async function () {
      try { var out = await api("/api/oauth/deny", { method: "POST", body: { client_id: c.clientId, redirect_uri: c.redirectUri, state: c.state } }); location.href = out.redirect; }
      catch (e) { location.href = "/app"; }
    });

    document.getElementById("approve").addEventListener("click", async function () {
      var btn = document.getElementById("approve");
      var errBox = document.getElementById("err");
      errBox.innerHTML = "";
      btn.disabled = true; btn.textContent = "Authorizing…";
      try {
        var keyBytes = cachedKey();
        if (!keyBytes) { errBox.innerHTML = '<div class="err">Your key is locked. <a href="/login?next=' + encodeURIComponent(location.pathname + location.search) + '">Sign in again</a> to unlock it.</div>'; btn.disabled = false; btn.textContent = "Continue"; return; }
        var keyBlob = null;
        if (c.cliPubkey) keyBlob = await wrapForCli(c.cliPubkey, keyBytes);
        var out = await api("/api/oauth/approve", { method: "POST", body: {
          client_id: c.clientId, redirect_uri: c.redirectUri, state: c.state, scope: c.scopes,
          code_challenge: c.codeChallenge, code_challenge_method: c.codeChallengeMethod, key_blob: keyBlob,
        } });
        location.href = out.redirect;
      } catch (error) {
        errBox.innerHTML = '<div class="err">' + esc(error.message) + "</div>";
        btn.disabled = false; btn.textContent = "Continue";
      }
    });
  }

  /* ----------------------------- dashboard ------------------------------ */
  var state = { me: null, keys: [], apps: [], sessions: [], plugin: null, tab: "overview", storeKeys: null, pendingToken: null, pendingSecret: null, decoded: {} };

  function fmtDate(ms) { if (!ms) return "—"; try { return new Date(ms).toLocaleString(); } catch (e) { return String(ms); } }

  function renderDashboard() {
    showSplash("Loading your workspace…");
    var tasks = [
      { key: "me", run: function () { return api("/api/me"); } },
      { key: "keys", run: function () { return api("/api/keys"); } },
      { key: "apps", run: function () { return api("/api/apps"); } },
      { key: "sessions", run: function () { return api("/api/sessions"); } },
      { key: "plugin", run: function () { return api("/plugin/latest.json"); } },
    ];
    var done = 0;
    var results = {};
    return Promise.all(tasks.map(function (t) {
      return t.run().then(function (value) { results[t.key] = value; }).catch(function (error) { results[t.key] = { __error: error }; }).finally(function () {
        done++; setProgress(8 + (done / tasks.length) * 92);
      });
    })).then(async function () {
      state.me = results.me;
      if (state.me && state.me.__error && state.me.__error.status === 401) { location.href = "/login?next=/app"; return; }
      state.keys = (results.keys && results.keys.keys) || [];
      state.apps = (results.apps && results.apps.apps) || [];
      state.sessions = (results.sessions && results.sessions.sessions) || [];
      state.plugin = results.plugin && !results.plugin.__error ? results.plugin : null;
      var keyBytes = cachedKey();
      if (keyBytes) { try { state.storeKeys = await storeKeys(keyBytes); } catch (e) { state.storeKeys = null; } }
      try { state.pendingToken = sessionStorage.getItem("sf_default_token"); if (state.pendingToken) sessionStorage.removeItem("sf_default_token"); } catch (e) {}
      hideSplash();
      renderDashboardShell();
    });
  }

  function renderDashboardShell() {
    var email = state.me && state.me.user ? state.me.user.email : "";
    var id = state.me && state.me.user ? state.me.user.id : "";
    root().innerHTML =
      '<div class="topbar fade"><div class="brand"><span class="brand-dot"></span> safestore</div>' +
      '<span class="pill on">' + esc(email) + "</span>" + '<span class="spacer"></span>' +
      '<button class="ghost" id="logout">Sign out</button></div>' +
      '<div class="tabs">' +
      tabButton("overview", "Overview") + tabButton("data", "Data") + tabButton("keys", "API keys") + tabButton("apps", "Apps") +
      "</div><div id=\"tab\"></div>";

    document.getElementById("logout").addEventListener("click", async function () {
      await api("/api/auth/logout", { method: "POST" }); try { sessionStorage.clear(); } catch (e) {} location.href = "/login";
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-tab]"), function (button) {
      button.addEventListener("click", function () { showTab(button.getAttribute("data-tab")); });
    });
    showTab("overview");
  }

  function tabButton(id, label) {
    return '<button data-tab="' + id + '" id="tab-' + id + '"' + (state.tab === id ? ' class="active"' : "") + ">" + esc(label) + "</button>";
  }

  function showTab(id) {
    state.tab = id;
    Array.prototype.forEach.call(document.querySelectorAll("[data-tab]"), function (button) {
      button.className = button.getAttribute("data-tab") === id ? "active" : "";
    });
    var box = document.getElementById("tab");
    if (id === "overview") box.innerHTML = overviewView();
    else if (id === "data") box.innerHTML = dataView();
    else if (id === "keys") { box.innerHTML = keysView(); wireKeys(); }
    else if (id === "apps") { box.innerHTML = appsView(); wireApps(); }
    if (id === "overview") wireOverview();
    if (id === "data") wireData();
  }

  function overviewView() {
    var id = state.me && state.me.user ? state.me.user.id : "";
    var tokenBanner = state.pendingToken
      ? '<div class="okbox">Your first API token was created. Copy it now — it is shown only once.<div class="token">' + esc(state.pendingToken) + '</div><button class="ghost small" id="dismiss-token" style="margin-top:8px">Dismiss</button></div>'
      : "";
    return '<div class="grid2 fade"><div class="card">' + tokenBanner +
      "<h2>Your account</h2>" +
      '<div class="kv"><div class="k">Account ID</div><div class="mono small">' + esc(id) + "</div>" +
      '<div class="k">Email</div><div>' + esc(state.me && state.me.user ? state.me.user.email : "") + "</div>" +
      '<div class="k">Cloud URL</div><div class="mono small">' + esc(location.origin) + "</div>" +
      '<div class="k">Sessions</div><div>' + state.sessions.length + "</div></div></div>" +
      '<div class="card"><h2>Connect a device</h2>' +
      '<p class="small muted">Install the CLI, then run:</p>' +
      '<div class="token">sf auth login</div>' +
      '<p class="small muted" style="margin-top:12px">It opens this site, asks you to approve access, then installs the plugin into OpenCode automatically.</p>' +
      (state.plugin ? '<p class="small muted">Cloud plugin version: <code>' + esc(state.plugin.version) + "</code></p>" : "") +
      '<div style="margin-top:14px"><h3>Install the cloud plugin</h3><p class="small muted">Recommended: use the CLI. It installs the plugin and your credentials automatically.</p>' +
      '<div class="token">sf auth login</div><p class="small muted" style="margin-top:10px">Manual install (advanced): download the bundle from ' +
      '<a href="/plugin/latest.js" target="_blank" rel="noopener">/plugin/latest.js</a> into <code>~/.config/opencode/plugins/opencode-safestore.js</code>, and create ' +
      '<code>~/.config/opencode/opencode-safestore.json</code> with your API key and master key.</p></div>' +
      "</div></div>";
  }
  function wireOverview() {
    var dismiss = document.getElementById("dismiss-token");
    if (dismiss) dismiss.addEventListener("click", function () { state.pendingToken = null; showTab("overview"); });
  }

  function dataView() {
    var rows = state.sessions;
    var inner = rows.length === 0
      ? '<div class="item muted">No memory sessions yet. They appear here once OpenCode syncs with your account.</div>'
      : rows.map(function (session) {
          var title = state.decoded["t:" + session.table_name];
          var label = title || ("Encrypted session " + session.table_name.slice(4, 12));
          return '<div class="item"><div class="row"><div><div class="title">' + esc(label) + "</div>" +
            '<div class="small muted mono">' + esc(session.table_name) + "</div></div><span class=\"spacer\"></span>" +
            '<button class="ghost" data-view="' + esc(session.table_name) + '">View</button>' +
            '<button class="danger" data-del="' + esc(session.table_name) + '">Delete</button></div>' +
            '<div class="small muted" style="margin-top:8px">' + session.message_count + " records · updated " + esc(fmtDate(session.updated_at)) + "</div>" +
            '<div id="msgs-' + esc(session.table_name) + '"></div></div>';
        }).join("");
    var unlocked = state.storeKeys ? '<span class="pill on">key unlocked</span>' : '<span class="pill off">key locked</span>';
    return '<div class="card fade"><div class="row"><h2 style="margin:0">Your encrypted data</h2><span class="spacer"></span>' + unlocked + "</div>" +
      '<p class="small muted">Bodies are decrypted in your browser with your key. The server only stores ciphertext.</p>' +
      '<div class="list" style="margin-top:12px">' + inner + "</div></div>";
  }
  function wireData() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-del]"), function (button) {
      button.addEventListener("click", async function () {
        var table = button.getAttribute("data-del");
        if (!confirm("Delete this session permanently?")) return;
        try { await api("/api/sessions/" + table, { method: "DELETE" }); state.sessions = state.sessions.filter(function (s) { return s.table_name !== table; }); showTab("data"); }
        catch (e) { toast(e.message, true); }
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-view]"), function (button) {
      button.addEventListener("click", async function () {
        var table = button.getAttribute("data-view");
        var box = document.getElementById("msgs-" + table);
        if (!state.storeKeys) { box.innerHTML = '<div class="err">Sign in again to unlock your key, then retry.</div>'; return; }
        box.innerHTML = '<p class="small muted">Decrypting…</p>';
        try {
          var out = await api("/api/sessions/" + table + "/messages?limit=500");
          var records = out.messages || [];
          var decoded = [];
          for (var i = 0; i < records.length; i++) {
            var value = await decryptRecord(state.storeKeys, records[i]);
            decoded.push({ record: records[i], value: value });
          }
          box.innerHTML = decoded.map(function (entry, index) {
            var text = entry.value === undefined ? "[could not decrypt]" : JSON.stringify(entry.value, null, 2);
            return '<div class="item" style="margin-top:8px"><div class="small muted">#' + (index + 1) + " · " + esc(fmtDate(entry.record.created_at)) + "</div>" +
              '<pre class="mono small" style="white-space:pre-wrap;word-break:break-word;margin:6px 0 0">' + esc(text) + "</pre></div>";
          }).join("") || '<div class="item muted">No records.</div>';
        } catch (e) { box.innerHTML = '<div class="err">' + esc(e.message) + "</div>"; }
      });
    });
  }

  function keysView() {
    var list = state.keys.length === 0
      ? '<div class="item muted">No API keys yet.</div>'
      : state.keys.map(function (key) {
          return '<div class="item"><div class="row"><div><div class="title">' + esc(key.name) + '</div><div class="small muted mono">' + esc(key.prefix) + "…</div></div>" +
            "<span class=\"spacer\"></span>" + (key.revoked_at ? '<span class="pill off">revoked</span>' : '<button class="danger" data-revoke="' + esc(key.id) + '">Revoke</button>') + "</div>" +
            '<div class="small muted" style="margin-top:6px">Scopes: ' + esc(key.scopes) + " · created " + esc(fmtDate(key.created_at)) + (key.last_used_at ? " · last used " + esc(fmtDate(key.last_used_at)) : "") + "</div></div>";
        }).join("");
    return '<div class="card fade"><h2>API keys</h2><p class="small muted">These are the tokens the plugin/CLI use to talk to the cloud. The safestore key is separate and never leaves your device.</p>' +
      '<div class="list" style="margin:12px 0">' + list + "</div>" +
      '<h3>Create a key</h3><label>Name</label><input id="key-name" placeholder="laptop">' +
      '<div class="row wrap" style="margin-top:10px"><label style="margin:0"><input type="checkbox" id="sc-read" checked style="width:auto"> store:read</label>' +
      '<label style="margin:0"><input type="checkbox" id="sc-write" checked style="width:auto"> store:write</label></div>' +
      '<div style="margin-top:12px"><button class="primary" id="create-key">Create key</button></div>' +
      '<div id="key-out"></div></div>';
  }
  function wireKeys() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-revoke]"), function (button) {
      button.addEventListener("click", async function () {
        try { await api("/api/keys/" + button.getAttribute("data-revoke"), { method: "DELETE" }); await refresh(); showTab("keys"); }
        catch (e) { toast(e.message, true); }
      });
    });
    document.getElementById("create-key").addEventListener("click", async function () {
      var scopes = [];
      if (document.getElementById("sc-read").checked) scopes.push("store:read");
      if (document.getElementById("sc-write").checked) scopes.push("store:write");
      try {
        var out = await api("/api/keys", { method: "POST", body: { name: document.getElementById("key-name").value.trim() || "api key", scopes: scopes } });
        document.getElementById("key-out").innerHTML = '<div class="okbox">Copy this token now — it is shown only once.<div class="token">' + esc(out.token) + "</div></div>";
        await refresh();
      } catch (e) { toast(e.message, true); }
    });
  }

  function appsView() {
    var list = state.apps.length === 0
      ? '<div class="item muted">No apps yet.</div>'
      : state.apps.map(function (app) {
          return '<div class="item"><div class="row"><div><div class="title">' + esc(app.name) + '</div><div class="small muted mono">' + esc(app.id) + "</div></div>" +
            "<span class=\"spacer\"></span><button class=\"danger\" data-delapp=\"" + esc(app.id) + '">Delete</button></div>' +
            '<div class="small muted" style="margin-top:6px">Redirects: ' + esc((app.redirect_uris || []).join(", ")) + "</div>" +
            '<div class="small muted">Scopes: ' + esc((app.scopes || []).join(" ")) + (app.api_url ? " · API " + esc(app.api_url) : "") + "</div></div>";
        }).join("");
    return '<div class="card fade"><h2>OAuth apps</h2><p class="small muted">Register an app to let it request access to your sessions. The app key authenticates the token exchange.</p>' +
      '<div class="list" style="margin:12px 0">' + list + "</div>" +
      "<h3>Create an app</h3><label>App name</label><input id=\"app-name\" placeholder=\"My integration\">" +
      '<label>Callback / redirect URLs (one per line)</label><textarea id="app-redirect" rows="2" placeholder="https://example.com/callback"></textarea>' +
      '<label>API URL (JS)</label><input id="app-api" placeholder="https://example.com/api">' +
      '<label>Permissions it needs</label><div class="row wrap"><label style="margin:0"><input type="checkbox" id="app-read" checked style="width:auto"> store:read</label>' +
      '<label style="margin:0"><input type="checkbox" id="app-write" checked style="width:auto"> store:write</label></div>' +
      '<div style="margin-top:12px"><button class="primary" id="create-app">Create app</button></div>' +
      '<div id="app-out"></div></div>';
  }
  function wireApps() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-delapp]"), function (button) {
      button.addEventListener("click", async function () {
        try { await api("/api/apps/" + button.getAttribute("data-delapp"), { method: "DELETE" }); await refresh(); showTab("apps"); }
        catch (e) { toast(e.message, true); }
      });
    });
    document.getElementById("create-app").addEventListener("click", async function () {
      var scopes = [];
      if (document.getElementById("app-read").checked) scopes.push("store:read");
      if (document.getElementById("app-write").checked) scopes.push("store:write");
      var redirects = document.getElementById("app-redirect").value.split("\n").map(function (s) { return s.trim(); }).filter(Boolean);
      try {
        var out = await api("/api/apps", { method: "POST", body: {
          name: document.getElementById("app-name").value.trim(),
          redirect_uris: redirects, scopes: scopes, api_url: document.getElementById("app-api").value.trim(),
        } });
        document.getElementById("app-out").innerHTML = '<div class="okbox">App created. Client ID <code>' + esc(out.app.id) + '</code>. Copy the app key now — it is shown only once.<div class="token">' + esc(out.client_secret) + "</div></div>";
        await refresh();
      } catch (e) { toast(e.message, true); }
    });
  }

  async function refresh() {
    try {
      var results = await Promise.all([api("/api/keys"), api("/api/apps"), api("/api/sessions")]);
      state.keys = results[0].keys || []; state.apps = results[1].apps || []; state.sessions = results[2].sessions || [];
    } catch (e) {}
  }

  /* ------------------------------- router ------------------------------- */
  if (boot.route === "signup") renderSignup();
  else if (boot.route === "login") renderLogin();
  else if (boot.route === "consent") renderConsent();
  else renderDashboard();
})();
