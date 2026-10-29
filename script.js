(function () {
  'use strict';

  var KEY = 'zharab.v1';
  var $ = function (id) { return document.getElementById(id); };

  /* ---------- Persistent state (LocalStorage) ---------- */
  function load() {
    try { return Object.assign({ seen: false, alerts: 0 }, JSON.parse(localStorage.getItem(KEY) || '{}')); }
    catch (e) { return { seen: false, alerts: 0 }; }
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(store)); } catch (e) { /* storage unavailable */ } }
  var store = load();

  /* ---------- Simulated host ---------- */
  var BASE = [
    ['System', 'SYSTEM', 1.2, true], ['smss.exe', 'SYSTEM', 0.1, true], ['csrss.exe', 'SYSTEM', 0.4, true],
    ['winlogon.exe', 'SYSTEM', 0.2, true], ['services.exe', 'SYSTEM', 0.3, true], ['lsass.exe', 'SYSTEM', 0.5, true],
    ['svchost.exe', 'NETWORK SERVICE', 1.1, true], ['explorer.exe', 'user', 2.4, true], ['chrome.exe', 'user', 6.8, true],
    ['code.exe', 'user', 3.9, true], ['Spotify.exe', 'user', 1.6, true], ['backupd.exe', 'user', 0.8, true]
  ];
  var procs = [];
  var pidSeq = 400;
  var scanned = 0;
  var cluster = null;

  function seedProcs() {
    procs = BASE.map(function (b) {
      pidSeq += 4 + Math.floor(Math.random() * 40);
      return { pid: pidSeq, name: b[0], user: b[1], cpu: b[2], signed: b[3], status: 'Running', threat: false };
    });
    scanned = procs.length;
  }

  function badge(text, cls) { return '<span class="badge ' + cls + '">' + text + '</span>'; }

  function renderProcs() {
    var body = $('procBody');
    body.textContent = '';
    procs.forEach(function (p) {
      if (p.status === 'Killed') return;
      var tr = document.createElement('tr');
      if (p.threat) tr.className = 'threat';
      var cells = [p.pid, p.name, p.user, p.cpu.toFixed(1) + '%'];
      cells.forEach(function (c) { var td = document.createElement('td'); td.textContent = c; tr.appendChild(td); });
      var sig = document.createElement('td'); sig.innerHTML = p.signed ? badge('Signed', 'ok') : badge('Unsigned', 'danger'); tr.appendChild(sig);
      var st = document.createElement('td');
      st.innerHTML = p.status === 'Suspended' ? badge('Suspended', 'warn') : p.threat ? badge('Hijacked', 'danger') : badge(p.status, 'ok');
      tr.appendChild(st);
      body.appendChild(tr);
    });
    $('procCount').textContent = procs.filter(function (p) { return p.status !== 'Killed'; }).length + ' running';
  }

  /* ---------- Counters ---------- */
  function renderStats() {
    $('statScanned').textContent = scanned.toLocaleString('en-US');
    $('statAlerts').textContent = store.alerts;
    var mode = 'Governing', note = 'All behavior within policy', alert = false;
    if (cluster && cluster.state === 'active') { mode = 'Under attack'; note = 'Threat cluster awaiting your decision'; alert = true; }
    else if (cluster && cluster.state === 'suspended') { mode = 'Contained'; note = 'Cluster frozen, state preserved for review'; }
    else if (cluster && cluster.state === 'killed') { mode = 'Recovered'; note = 'Cluster terminated, review hardening advice'; }
    $('statMode').textContent = mode;
    $('statMode').classList.toggle('alert', alert);
    $('statModeNote').textContent = note;
  }

  /* ---------- Chart ---------- */
  var chart, cpuData = [], ramData = [], labels = [];
  function initChart() {
    for (var i = 0; i < 30; i++) { labels.push(''); cpuData.push(18 + Math.random() * 6); ramData.push(48 + Math.random() * 3); }
    if (typeof Chart === 'undefined') { $('chart').parentNode.innerHTML = '<p class="muted">Chart.js failed to load. Check your connection.</p>'; return; }
    var ctx = $('chart').getContext('2d');
    var g1 = ctx.createLinearGradient(0, 0, 0, 300); g1.addColorStop(0, 'rgba(124,58,237,.55)'); g1.addColorStop(1, 'rgba(124,58,237,0)');
    var g2 = ctx.createLinearGradient(0, 0, 0, 300); g2.addColorStop(0, 'rgba(103,232,249,.3)'); g2.addColorStop(1, 'rgba(103,232,249,0)');
    chart = new Chart(ctx, {
      type: 'line',
      data: { labels: labels, datasets: [
        { label: 'CPU %', data: cpuData, borderColor: '#A78BFA', backgroundColor: g1, fill: true, tension: .4, pointRadius: 0, borderWidth: 2.5 },
        { label: 'RAM %', data: ramData, borderColor: '#67E8F9', backgroundColor: g2, fill: true, tension: .4, pointRadius: 0, borderWidth: 2.5 }
      ] },
      options: {
        responsive: true, maintainAspectRatio: false, animation: { duration: 600 },
        interaction: { intersect: false, mode: 'index' },
        scales: { y: { min: 0, max: 100, grid: { color: 'rgba(226,232,240,.08)' }, ticks: { color: '#94A3B8' } }, x: { display: false } },
        plugins: { legend: { labels: { color: '#E2E8F0', usePointStyle: true } } }
      }
    });
  }

  function tick() {
    var spike = cluster && cluster.state === 'active';
    var lastC = cpuData[cpuData.length - 1], lastR = ramData[ramData.length - 1];
    var targetC = spike ? 72 : 22, targetR = spike ? 68 : 49;
    var c = Math.max(3, Math.min(98, lastC + (targetC - lastC) * .25 + (Math.random() - .5) * 6));
    var r = Math.max(20, Math.min(95, lastR + (targetR - lastR) * .15 + (Math.random() - .5) * 2));
    cpuData.push(c); ramData.push(r); labels.push(''); cpuData.shift(); ramData.shift(); labels.shift();
    if (chart) chart.update();
    procs.forEach(function (p) {
      if (p.status === 'Running') p.cpu = Math.max(0.1, p.cpu + (Math.random() - .5) * .6);
      if (p.status === 'Suspended') p.cpu = 0;
    });
    if (Math.random() < .6) scanned += 1 + Math.floor(Math.random() * 3);
    renderProcs(); renderStats();
  }

  /* ---------- Threat cluster ---------- */
  function simulateCluster() {
    if (cluster && cluster.state === 'active') { toast('A threat cluster is already active. Resolve it first.'); return; }
    var base = pidSeq + 100;
    var host = procs.filter(function (p) { return p.name === 'explorer.exe'; })[0];
    host.threat = true;
    var inj = { pid: base, name: 'updater_helper.exe', user: 'user', cpu: 4.2, signed: false, status: 'Running', threat: true, role: 'Injector (unsigned, API permission abuse)' };
    var kids = [
      { pid: base + 12, name: 'cmd.exe', user: 'user', cpu: 3.1, signed: true, status: 'Running', threat: true, role: 'Child of explorer.exe, hidden console' },
      { pid: base + 20, name: 'powershell.exe', user: 'user', cpu: 8.7, signed: true, status: 'Running', threat: true, role: 'Encoded command, privilege escalation' },
      { pid: base + 28, name: 'svc_sync.exe', user: 'SYSTEM', cpu: 5.5, signed: false, status: 'Running', threat: true, role: 'Elevated payload, fork/join fan-out' }
    ];
    procs.push(inj); kids.forEach(function (k) { procs.push(k); });
    scanned += 4;
    store.alerts += 3; save();
    cluster = { state: 'active', host: host, members: [host, inj].concat(kids) };
    renderCluster(); renderProcs(); renderStats();
    toast('High-impact alert: explorer.exe was hijacked by an unsigned helper.');
    $('clusterCard').scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function renderCluster() {
    var card = $('clusterCard');
    if (!cluster) { card.hidden = true; return; }
    card.hidden = false;
    var tag = { active: ['Active', 'danger'], suspended: ['Suspended', 'warn'], killed: ['Killed', 'ok'] }[cluster.state];
    $('clusterTitle').textContent = 'Threat Cluster: explorer.exe hijack';
    $('clusterState').textContent = tag[0]; $('clusterState').className = 'badge ' + tag[1];
    $('clusterDesc').textContent = 'Five related processes share one injection chain. Acting on the cluster handles them together.';
    var tree = $('clusterTree'); tree.textContent = '';
    var roles = ['Hijacked host (legitimate, signed)', null];
    cluster.members.forEach(function (m, i) {
      var li = document.createElement('li');
      var depth = i < 2 ? 0 : 1;
      li.style.marginLeft = depth * 22 + 'px';
      var b = document.createElement('b'); b.textContent = m.name;
      var pid = document.createElement('span'); pid.textContent = 'PID ' + m.pid;
      var s = document.createElement('small'); s.textContent = i === 0 ? roles[0] : m.role;
      li.appendChild(b); li.appendChild(pid); li.appendChild(s);
      tree.appendChild(li);
    });
    var done = cluster.state !== 'active';
    $('btnSuspend').disabled = done; $('btnKill').disabled = done && cluster.state !== 'suspended';
  }

  /* ---------- Consequence modal ---------- */
  var pending = null;
  var COPY = {
    suspend: {
      title: 'Suspend this cluster?',
      body: '<p>All five processes are frozen in place. Memory and handles stay intact, so you can inspect exactly what the injector wrote into explorer.exe.</p><p><b>Impact:</b> Your desktop shell and taskbar will freeze until you resume or restart it. No data is destroyed.</p>',
      gold: 'Suspend first, investigate, then kill. It is the safest order and preserves forensic evidence.', cls: 'warn', label: 'Suspend Cluster'
    },
    kill: {
      title: 'Kill this cluster?',
      body: '<p>All five processes are terminated immediately. explorer.exe was hijacked because updater_helper.exe, an unsigned program, was allowed to write code into it through a granted API permission. The injected code then spawned cmd.exe and powershell.exe as normal-looking children.</p><p><b>Impact:</b> The attack chain ends, but unsaved work in explorer.exe is lost, and volatile evidence is erased.</p>',
      gold: 'Next time, avoid granting arbitrary unsigned API permissions and block unsigned binaries from injecting into shell processes.', cls: 'danger', label: 'Kill Cluster'
    }
  };

  function openAction(kind) {
    if (!cluster) return;
    pending = kind;
    var c = COPY[kind];
    $('actionTitle').textContent = c.title;
    $('actionBody').innerHTML = c.body + '<div class="gold"><b>Golden recommendation.</b> ' + c.gold + '</div>';
    var btn = $('actionConfirm'); btn.className = 'btn ' + c.cls; btn.textContent = c.label;
    $('actionModal').hidden = false; btn.focus();
  }

  function applyAction() {
    if (!pending || !cluster) return;
    var kind = pending; pending = null;
    cluster.members.forEach(function (m) {
      if (kind === 'suspend') { m.status = 'Suspended'; }
      else { m.status = 'Killed'; m.threat = false; }
    });
    if (kind === 'kill') {
      cluster.host.status = 'Running'; cluster.host.threat = false; cluster.state = 'killed';
      procs = procs.filter(function (p) { return cluster.members.indexOf(p) === -1 || p === cluster.host; });
    } else { cluster.state = 'suspended'; }
    $('actionModal').hidden = true;
    renderCluster(); renderProcs(); renderStats();
    toast(kind === 'suspend' ? 'Cluster suspended. Evidence preserved.' : 'Cluster killed. Review the recommendation above.');
  }

  /* ---------- Ask Zharab (local knowledge base) ---------- */
  var KB = [
    { k: ['bypass', 'defense', 'evade'], a: 'The attacker never ran as an obvious threat. An unsigned helper used an over-broad API permission to write code into explorer.exe, a trusted signed process. Defenses that trust the host process by name saw nothing wrong. Zharab judges behavior: who is injecting into whom, and why.' },
    { k: ['fork', 'join'], a: 'A Fork/Join anomaly is a process tree that fans out into several children and then converges, for example one process spawning cmd, powershell and a payload that all report back to the same parent. Normal software rarely does this. It is a common marker of automated post-exploitation.' },
    { k: ['prevent', 'escalation', 'privilege'], a: 'To prevent privilege escalation:\n1. Grant least privilege and never hand out arbitrary API permissions.\n2. Require signatures for anything that touches shell processes.\n3. Keep standard users out of admin groups.\n4. Patch quickly.\n5. Alert on child processes that run with higher rights than their parent.' },
    { k: ['inject'], a: 'Process injection writes foreign code into a running trusted process so the code inherits its identity and permissions. Watch for cross-process memory writes and remote thread creation from unsigned binaries.' },
    { k: ['edr', 'difference', 'cloud'], a: 'Zharab is local-first: analysis and decisions stay on your device, and it suspends before it terminates. Traditional EDRs usually upload telemetry to the cloud and kill processes aggressively, which can break workloads and destroy evidence.' },
    { k: ['suspend', 'kill'], a: 'Suspend freezes a cluster and keeps memory for investigation. Kill ends it instantly but loses volatile evidence and unsaved work. Suspend first when you are unsure.' },
    { k: ['privacy', 'local', 'data'], a: 'Everything runs in this browser. Alerts and settings sit in LocalStorage, and no process data is sent anywhere.' },
    { k: ['hello', 'hi', 'hey'], a: 'Hello. I am Zharab. Ask me about injection, Fork/Join anomalies, or how to harden this host.' }
  ];
  var CHIPS = ['How did this process bypass defenses?', 'What is a Fork/Join anomaly?', 'How to prevent privilege escalation?', 'How is Zharab different from an EDR?'];

  function addMsg(text, who) {
    var d = document.createElement('div'); d.className = 'msg ' + who; d.textContent = text;
    var log = $('chatLog'); log.appendChild(d); log.scrollTop = log.scrollHeight; return d;
  }
  function answer(q) {
    var s = q.toLowerCase();
    for (var i = 0; i < KB.length; i++) {
      for (var j = 0; j < KB[i].k.length; j++) { if (s.indexOf(KB[i].k[j]) !== -1) return KB[i].a; }
    }
    return 'I can discuss process injection, Fork/Join anomalies, privilege escalation, suspend versus kill, and how Zharab differs from an EDR. Try one of the suggested questions.';
  }
  function ask(q) {
    q = q.trim(); if (!q) return;
    addMsg(q, 'me'); $('chatInput').value = '';
    var bot = addMsg('Analyzing…', 'bot');
    setTimeout(function () { bot.textContent = answer(q); $('chatLog').scrollTop = $('chatLog').scrollHeight; }, 450);
  }

  /* ---------- Helpers ---------- */
  var toastTimer;
  function toast(t) {
    var el = $('toast'); el.textContent = t; el.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(function () { el.hidden = true; }, 3800);
  }
  function closeIntro() { $('introModal').hidden = true; store.seen = true; save(); }

  /* ---------- Init ---------- */
  function init() {
    seedProcs(); renderProcs(); renderStats(); initChart();
    CHIPS.forEach(function (c) {
      var b = document.createElement('button'); b.type = 'button'; b.textContent = c;
      b.addEventListener('click', function () { ask(c); }); $('chips').appendChild(b);
    });
    addMsg('I am Zharab. Simulate a threat cluster, then ask me how it worked.', 'bot');

    $('btnSimulate').addEventListener('click', simulateCluster);
    $('btnSuspend').addEventListener('click', function () { openAction('suspend'); });
    $('btnKill').addEventListener('click', function () { openAction('kill'); });
    $('actionConfirm').addEventListener('click', applyAction);
    $('actionCancel').addEventListener('click', function () { pending = null; $('actionModal').hidden = true; });
    $('introClose').addEventListener('click', closeIntro);
    $('introModal').addEventListener('click', function (e) {
      if (e.target === this) closeIntro();
    });
    $('btnIntro').addEventListener('click', function () { $('introModal').hidden = false; $('introClose').focus(); });
    $('btnReset').addEventListener('click', function () {
      store = { seen: true, alerts: 0 }; save(); cluster = null; seedProcs();
      $('clusterCard').hidden = true; renderProcs(); renderStats(); toast('Session reset.');
    });
    $('chatSend').addEventListener('click', function () { ask($('chatInput').value); });
    $('chatInput').addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); ask(e.target.value); } });
    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape') return;
      if (!$('actionModal').hidden) { pending = null; $('actionModal').hidden = true; }
      else if (!$('introModal').hidden) closeIntro();
    });

    if (!store.seen) { $('introModal').hidden = false; $('introClose').focus(); }
    setInterval(tick, 1500);
  }

  document.addEventListener('DOMContentLoaded', init);
})();
