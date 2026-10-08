const $ = (id) => document.getElementById(id);
let authMode = "login";
let authToken = localStorage.getItem("sentinel_token") || "";
let currentUser = null;
let currentStats = null;

function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

function toast(message, type = "ok") {
  const t = $("toast");
  t.textContent = message;
  t.className = `toast ${type}`;
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => t.classList.add("hidden"), 2800);
}

async function api(path, options = {}) {
  const headers = {...(options.headers || {})};
  if (!(options.body instanceof FormData) && options.body !== undefined) headers["Content-Type"] = "application/json";
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  const res = await fetch(path, {...options, headers});
  const contentType = res.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) throw new Error((data && data.detail) || "Request failed");
  return data;
}

function riskPill(risk) {
  const r = String(risk || "medium").toLowerCase();
  return `<span class="pill ${escapeHtml(r)}">${escapeHtml(r.toUpperCase())}</span>`;
}
function initials(name) { return String(name || "SA").split(/\s+/).filter(Boolean).slice(0,2).map(x=>x[0]).join("").toUpperCase() || "SA"; }
function showAuth(){ $("authGate").classList.remove("hidden"); }
function hideAuth(){ $("authGate").classList.add("hidden"); }

function setAuthMode(mode){
  authMode = mode;
  const reg = mode === "register";
  $("loginTab").classList.toggle("active", !reg); $("registerTab").classList.toggle("active", reg);
  $("nameField").classList.toggle("hidden", !reg);
  $("authTitle").textContent = reg ? "Create your account" : "Welcome back";
  $("authSubtitle").textContent = reg ? "Register for a private SentinelAI workspace." : "Sign in to access your private security dashboard.";
  $("authSubmit").textContent = reg ? "Create account" : "Login";
  $("authPassword").autocomplete = reg ? "new-password" : "current-password";
  $("authMessage").textContent = "";
}

$("loginTab").addEventListener("click", ()=>setAuthMode("login"));
$("registerTab").addEventListener("click", ()=>setAuthMode("register"));
$("authForm").addEventListener("submit", async (e)=>{
  e.preventDefault();
  const msg = $("authMessage"); msg.className = "auth-message"; msg.textContent = "Connecting…";
  const body = {email: $("authEmail").value.trim(), password: $("authPassword").value};
  if(authMode === "register") body.name = $("authName").value.trim();
  try{
    const d = await api(authMode === "register" ? "/api/auth/register" : "/api/auth/login", {method:"POST", body:JSON.stringify(body)});
    authToken = d.token; localStorage.setItem("sentinel_token", authToken); currentUser = d.user;
    msg.className = "auth-message ok"; msg.textContent = "Access granted.";
    hideAuth(); await bootstrapDashboard();
  }catch(err){ msg.textContent = err.message; }
});

async function logoutNow(){
  try{ await api("/api/auth/logout", {method:"POST"}); }catch{}
  authToken = ""; currentUser = null; currentStats = null; localStorage.removeItem("sentinel_token"); closeProfile(); showAuth();
}
$("drawerLogout").addEventListener("click", logoutNow);

function openProfile(){
  if(!currentUser) return;
  $("profileDrawer").classList.add("open"); $("profileDrawer").setAttribute("aria-hidden", "false"); $("drawerShade").classList.remove("hidden");
}
function closeProfile(){
  $("profileDrawer").classList.remove("open"); $("profileDrawer").setAttribute("aria-hidden", "true"); $("drawerShade").classList.add("hidden");
}
$("profileButton").addEventListener("click", openProfile);
$("closeDrawer").addEventListener("click", closeProfile);
$("drawerShade").addEventListener("click", closeProfile);

document.addEventListener("keydown", (e)=>{ if(e.key === "Escape"){ closeProfile(); $("compareModal").classList.add("hidden"); }});

async function loadMe(){
  const d = await api("/api/auth/me"); currentUser = d.user; currentStats = d.stats;
  $("profileName").textContent = d.user.name; $("profileEmail").textContent = d.user.email; $("avatar").textContent = initials(d.user.name);
  $("statTotal").textContent = d.stats.total_scans; $("statAverage").textContent = `${d.stats.average_score}/100`; $("statHigh").textContent = d.stats.high_risk; $("statBest").textContent = `${d.stats.best_score}/100`;
  $("drawerAvatar").textContent = initials(d.user.name); $("drawerName").textContent = d.user.name; $("drawerEmail").textContent = d.user.email;
  $("drawerSince").textContent = `Member since ${new Date(d.user.created_at).toLocaleDateString()}`;
  $("drawerTotal").textContent = d.stats.total_scans; $("drawerAverage").textContent = `${d.stats.average_score}/100`; $("drawerBest").textContent = `${d.stats.best_score}/100`; $("drawerHigh").textContent = d.stats.high_risk;
  $("profileNameInput").value = d.user.name; $("profileEmailInput").value = d.user.email;
}

$("profileForm").addEventListener("submit", async (e)=>{
  e.preventDefault(); const msg=$("profileMessage"); msg.className="drawer-message"; msg.textContent="Saving…";
  try{
    const d = await api("/api/auth/profile", {method:"PUT", body:JSON.stringify({name:$("profileNameInput").value.trim(), email:$("profileEmailInput").value.trim()})});
    currentUser = d.user; msg.className="drawer-message ok"; msg.textContent="Profile updated."; await loadMe(); toast("Profile updated");
  }catch(err){ msg.textContent = err.message; }
});

$("passwordChangeForm").addEventListener("submit", async (e)=>{
  e.preventDefault(); const msg=$("passwordMessage"); msg.className="drawer-message";
  const current=$("currentPassword").value, next=$("newPassword").value, confirm=$("confirmPassword").value;
  if(next !== confirm){ msg.textContent="New passwords do not match."; return; }
  msg.textContent="Updating…";
  try{
    await api("/api/auth/change-password", {method:"POST", body:JSON.stringify({current_password:current,new_password:next})});
    msg.className="drawer-message ok"; msg.textContent="Password changed successfully."; $("passwordChangeForm").reset(); toast("Password updated");
  }catch(err){ msg.textContent=err.message; }
});

function downloadCsv(){
  fetch("/api/history/export.csv", {headers:{Authorization:`Bearer ${authToken}`}}).then(async res=>{
    if(!res.ok) throw new Error("Could not export history");
    const blob=await res.blob(), url=URL.createObjectURL(blob), a=document.createElement("a"); a.href=url; a.download="sentinelai-scan-history.csv"; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }).catch(err=>toast(err.message,"error"));
}
$("exportCsvButton").addEventListener("click", downloadCsv); $("exportHistoryTop").addEventListener("click", downloadCsv);

function setScore(score, risk){
  $("scoreRing").style.setProperty("--score", score); $("scoreValue").textContent = score; $("scoreRisk").innerHTML = `Risk level: <b class="${escapeHtml(risk)}">${escapeHtml(String(risk).toUpperCase())}</b>`;
}

function checklistFromScan(d) {
  const map = Object.fromEntries(d.findings.map(f => [f.name, f]));
  const https = map["HTTPS"], tls = map["TLS Certificate"], cors=map["CORS"], mixed=map["Mixed Content"];
  const headerNames=["HSTS","Content-Security-Policy","X-Content-Type-Options","X-Frame-Options","Referrer-Policy","Permissions-Policy"];
  const headerWarnings = headerNames.filter(n => map[n] && map[n].status !== "pass").length;
  $("securityChecklist").innerHTML = `
    <div class="security-row"><span><i class="dot green"></i> SSL / HTTPS</span><b class="${https?.status === "pass" ? "ok" : "warn"}">${https?.status === "pass" ? "Safe" : "Check"}</b></div>
    <div class="security-row"><span><i class="dot amber"></i> Security Headers</span><b class="${headerWarnings ? "warn" : "ok"}">${headerWarnings ? `${headerWarnings} issue${headerWarnings>1?"s":""}` : "Good"}</b></div>
    <div class="security-row"><span><i class="dot blue"></i> TLS Certificate</span><b class="${tls?.status === "pass" ? "ok" : "warn"}">${tls?.status === "pass" ? "Valid" : "Review"}</b></div>
    <div class="security-row"><span><i class="dot purple"></i> CORS / Content</span><b class="${cors?.status === "pass" && mixed?.status === "pass" ? "ok" : "warn"}">${cors?.status === "pass" && mixed?.status === "pass" ? "Good" : "Review"}</b></div>
    <div class="security-row"><span><i class="dot pink"></i> Risk Level</span><b class="${d.risk === "low" ? "ok" : "warn"}">${escapeHtml(String(d.risk).toUpperCase())}</b></div>`;
}

async function downloadReport(scanId) {
    try {
        if (!authToken) {
            throw new Error(
                "Authentication token not found. Please log in again."
            );
        }

        const response = await fetch(
            `/api/reports/${scanId}.pdf?t=${Date.now()}`,
            {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${authToken}`
                },
                cache: "no-store"
            }
        );

        if (!response.ok) {
            let message = `PDF download failed (${response.status})`;

            try {
                const data = await response.json();

                if (data.detail) {
                    message = data.detail;
                }
            } catch (_) {}

            throw new Error(message);
        }

        const contentType =
            response.headers.get("content-type") || "";

        if (!contentType.includes("application/pdf")) {
            throw new Error(
                "Server did not return a valid PDF file."
            );
        }

        const blob = await response.blob();

        if (!blob.size) {
            throw new Error(
                "Generated PDF file is empty."
            );
        }

        const fileUrl =
            window.URL.createObjectURL(blob);

        const link =
            document.createElement("a");

        link.href = fileUrl;
        link.download =
            `SentinelAI_Security_Report_${scanId}.pdf`;

        link.style.display = "none";

        document.body.appendChild(link);

        link.click();

        setTimeout(() => {
            link.remove();
            window.URL.revokeObjectURL(fileUrl);
        }, 5000);

    } catch (error) {

        console.error(
            "PDF DOWNLOAD ERROR:",
            error
        );

        if (typeof toast === "function") {
            toast(error.message, "error");
        } else {
            alert(error.message);
        }
    }
}

window.downloadReport = downloadReport;

async function compareScan(scanId){
  const box=$("compareContent"); $("compareModal").classList.remove("hidden"); box.innerHTML="Loading comparison…";
  try{
    const d=await api(`/api/compare/${scanId}`);
    if(!d.available){ box.innerHTML=`<div class="no-data">${escapeHtml(d.message)}</div>`; return; }
    const delta = d.score_delta > 0 ? `+${d.score_delta}` : String(d.score_delta);
    const changes = d.changed_findings.length ? d.changed_findings.map(x=>`<div class="change-item"><strong>${escapeHtml(x.name)}</strong><br><span>Before: ${escapeHtml(x.before?.detail || "—")}</span><br><span>Now: ${escapeHtml(x.after?.detail || "—")}</span></div>`).join("") : `<div class="no-data">No finding changes detected.</div>`;
    box.innerHTML=`<div class="compare-summary"><div><span>Previous score</span><strong>${d.previous.score}/100</strong></div><div><span>Current score</span><strong>${d.current.score}/100</strong></div><div><span>Change</span><strong>${escapeHtml(delta)}</strong></div></div>${changes}`;
  }catch(err){ box.innerHTML=`<div class="no-data">${escapeHtml(err.message)}</div>`; }
}
window.compareScan=compareScan;
$("closeCompare").addEventListener("click",()=>$("compareModal").classList.add("hidden"));
$("compareModal").addEventListener("click",e=>{if(e.target===$("compareModal")) $("compareModal").classList.add("hidden")});

$("scanForm").addEventListener("submit", async (e) => {
  e.preventDefault(); const box = $("scanResult"); box.classList.remove("hidden"); box.innerHTML = `<div class="result-head"><strong>Scanning target…</strong><span class="pill medium">processing</span></div>`;
  try {
    const d = await api("/api/scan", {method:"POST", body:JSON.stringify({url:$("scanUrl").value})});
    setScore(d.security_score, d.risk); checklistFromScan(d);
    const findings = d.findings.map(f => `<div class="finding-pill"><b>${escapeHtml(f.name)}</b><span class="pill ${escapeHtml(f.status)}">${escapeHtml(f.detail)}</span></div>`).join("");
    box.innerHTML = `<div class="result-head"><strong>Scan completed</strong>${riskPill(d.risk)}</div><div class="result-grid"><div class="result-box"><span>Final URL</span><strong>${escapeHtml(d.final_url)}</strong></div><div class="result-box"><span>HTTP Status</span><strong>${escapeHtml(d.http_status)}</strong></div><div class="result-box"><span>Resolved IP</span><strong>${escapeHtml((d.resolved_ips||[]).join(", "))}</strong></div></div><div class="advanced-meta"><div><span>Redirects</span><strong>${Math.max(0,(d.redirect_chain||[]).length-1)}</strong></div><div><span>robots.txt</span><strong>${d.robots_txt?"Found":"Not found"}</strong></div><div><span>sitemap.xml</span><strong>${d.sitemap_xml?"Found":"Not found"}</strong></div><div><span>Mixed content</span><strong>${escapeHtml(d.mixed_content_count)}</strong></div></div><div class="finding-grid" style="margin-top:10px">${findings}</div><div class="scan-actions"><button class="report-btn" onclick="downloadReport(${Number(d.scan_id)})">Download PDF Report</button><button class="compare-btn" onclick="compareScan(${Number(d.scan_id)})">Compare</button><button class="compare-btn" onclick="showRemediation(${Number(d.scan_id)})">Recommended Fixes</button></div>`;
    await Promise.all([loadHistory(), loadThreats(), loadMe()]); toast("Website scan completed");
  } catch (err) { box.innerHTML = `<div class="result-head"><strong>Scan failed</strong><span class="pill high">error</span></div>${escapeHtml(err.message)}`; }
});

$("domainForm").addEventListener("submit", async (e)=>{
  e.preventDefault(); const box=$("domainResult"); box.className="mini-result"; box.innerHTML="Querying public DNS…";
  try{
    const d=await api("/api/domain-intel",{method:"POST",body:JSON.stringify({url:$("domainInput").value})});
    const row=(name, arr)=>`<div><b>${name}</b><span>${escapeHtml((arr&&arr.length?arr:["None found"]).join(" • "))}</span></div>`;
    box.innerHTML=`<div class="domain-score"><span>Mail security score</span><strong>${escapeHtml(d.mail_security_score)}/100</strong></div><div class="domain-list">${row("A",d.a)}${row("AAAA",d.aaaa)}${row("MX",d.mx)}${row("NS",d.ns)}${row("SPF",d.spf)}${row("DMARC",d.dmarc)}${row("CAA",d.caa)}${row("DNSKEY",d.dnskey)}${row("PTR",d.ptr)}</div>`;
  }catch(err){box.innerHTML=`<span class="pill high">error</span> ${escapeHtml(err.message)}`;}
});

$("phishForm").addEventListener("submit", async (e)=>{ e.preventDefault(); const box=$("phishResult"); box.className="mini-result"; box.innerHTML="Analyzing URL…"; try{ const d=await api("/api/phishing",{method:"POST",body:JSON.stringify({url:$("phishUrl").value})}); box.innerHTML=`<div style="display:flex;justify-content:space-between;align-items:center"><strong>Risk ${d.risk_score}/100</strong>${riskPill(d.risk)}</div><div class="meter"><div style="width:${d.risk_score}%"></div></div><ul>${d.reasons.slice(0,5).map(x=>`<li>${escapeHtml(x)}</li>`).join("")}</ul>`;}catch(err){box.innerHTML=`<span class="pill high">error</span> ${escapeHtml(err.message)}`;}});

$("passwordForm").addEventListener("submit", async (e)=>{ e.preventDefault(); const box=$("passwordResult"); box.className="mini-result"; box.innerHTML="Checking password…"; try{ const d=await api("/api/password",{method:"POST",body:JSON.stringify({password:$("passwordInput").value})}); const cls=d.score>=65?"low":d.score>=40?"medium":"high"; box.innerHTML=`<div style="display:flex;justify-content:space-between;align-items:center"><strong>Score ${d.score}/100</strong><span class="pill ${cls}">${escapeHtml(d.label)}</span></div><div class="meter"><div style="width:${d.score}%"></div></div><div>Estimated entropy: <strong>${escapeHtml(d.entropy_bits_estimate)} bits</strong></div><ul>${d.feedback.slice(0,3).map(x=>`<li>${escapeHtml(x)}</li>`).join("")}</ul>`; $("passwordInput").value="";}catch(err){box.innerHTML=`<span class="pill high">error</span> ${escapeHtml(err.message)}`;}});

$("assistantForm").addEventListener("submit", async (e)=>{ e.preventDefault(); const box=$("assistantResult"); box.className="mini-result"; box.innerHTML="SentinelAI is thinking…"; try{ const d=await api("/api/assistant",{method:"POST",body:JSON.stringify({question:$("assistantQuestion").value})}); box.innerHTML=`<strong>SentinelAI</strong><br>${escapeHtml(d.answer)}`;}catch(err){box.innerHTML=`<span class="pill high">error</span> ${escapeHtml(err.message)}`;}});

async function loadHistory(){
  const box=$("history");
  try{
    const d=await api("/api/history?limit=8");
    if(!d.items.length){box.innerHTML=`<div class="no-data">No scans yet. Run your first website scan above.</div>`;return;}
    box.innerHTML=d.items.map(i=>`<div class="history-item"><div class="url">${escapeHtml(i.url)}</div><strong>${escapeHtml(i.score)}/100</strong>${riskPill(i.risk)}<div class="history-actions"><button class="report-btn" onclick="downloadReport(${Number(i.id)})">PDF</button><button class="compare-btn" onclick="compareScan(${Number(i.id)})">Compare</button><button class="compare-btn" onclick="showRemediation(${Number(i.id)})">Fixes</button></div></div>`).join("");
  }catch{box.innerHTML=`<div class="no-data">Could not load scan history.</div>`;}
}

async function loadThreats(){
  const box=$("threats"), trend=$("trendChart");
  try{
    const d=await api("/api/threats"), x=d.scan_risk_distribution, total=Math.max(1,(x.low||0)+(x.medium||0)+(x.high||0)), pct=n=>Math.round((n/total)*100);
    box.innerHTML=`<div class="threat-row"><span>Low risk</span><div class="bar-track"><div class="bar-fill" style="width:${pct(x.low)}%"></div></div><b>${x.low}</b></div><div class="threat-row"><span>Medium</span><div class="bar-track"><div class="bar-fill medium-bar" style="width:${pct(x.medium)}%"></div></div><b>${x.medium}</b></div><div class="threat-row"><span>High risk</span><div class="bar-track"><div class="bar-fill high-bar" style="width:${pct(x.high)}%"></div></div><b>${x.high}</b></div>`;
    if(d.score_trend.length){ trend.innerHTML=d.score_trend.map(p=>`<div class="trend-bar" data-score="${p.score}" title="${escapeHtml(new Date(p.created_at).toLocaleString())}" style="height:${Math.max(6,p.score)}%"></div>`).join(""); }
    else trend.innerHTML=`<div class="no-data" style="width:100%">Score trend appears after scans.</div>`;
  }catch{box.innerHTML=`<div class="no-data">Could not load threat overview.</div>`; trend.innerHTML="";}
}

async function bootstrapDashboard(){
  try{ await loadMe(); hideAuth(); await Promise.all([loadHistory(),loadThreats(),loadAssets(),loadNotifications()]); }
  catch{ authToken=""; localStorage.removeItem("sentinel_token"); showAuth(); }
}

document.querySelectorAll(".nav-item").forEach(item=>item.addEventListener("click",()=>{document.querySelectorAll(".nav-item").forEach(x=>x.classList.remove("active"));item.classList.add("active");}));
setAuthMode("login"); bootstrapDashboard();

// ---- SentinelAI v5: Monitoring, notifications, email/file analysis, remediation ----
function formatWhen(value){
  if(!value) return "Never";
  try{return new Date(value).toLocaleString();}catch{return value;}
}

async function loadAssets(){
  const box=$("assetList");
  if(!box) return;
  try{
    const d=await api("/api/assets");
    if(!d.items.length){ box.innerHTML='<div class="no-data">No monitored assets yet.</div>'; return; }
    box.innerHTML=d.items.map(a=>{
      const status=a.last_status || "pending";
      return `<div class="asset-item">
        <div class="asset-main"><strong>${escapeHtml(a.name)}</strong><span>${escapeHtml(a.url)}</span></div>
        <div class="asset-meta"><span class="asset-state ${escapeHtml(status)}">${escapeHtml(status.toUpperCase())}</span><br><small>${escapeHtml(a.last_http_status || "—")}</small></div>
        <div class="asset-meta"><strong>${escapeHtml(a.last_response_ms ?? "—")} ms</strong><br><small>${escapeHtml(formatWhen(a.last_checked_at))}</small></div>
        <div class="asset-actions"><button class="tiny-btn" onclick="checkAsset(${Number(a.id)})">Check now</button><button class="tiny-btn" onclick="showUptime(${Number(a.id)})">Uptime</button><button class="tiny-btn" onclick="toggleAsset(${Number(a.id)},${a.enabled?"false":"true"})">${a.enabled?"Pause":"Enable"}</button><button class="tiny-btn danger" onclick="removeAsset(${Number(a.id)})">Remove</button></div>
      </div>`;
    }).join("");
  }catch(err){box.innerHTML=`<div class="no-data">${escapeHtml(err.message)}</div>`;}
}

$("assetForm")?.addEventListener("submit",async e=>{
  e.preventDefault();
  try{
    await api("/api/assets",{method:"POST",body:JSON.stringify({name:$("assetName").value.trim(),url:$("assetUrl").value.trim(),interval_minutes:Number($("assetInterval").value)})});
    e.target.reset(); await Promise.all([loadAssets(),loadMe()]); toast("Monitor added");
  }catch(err){toast(err.message,"error");}
});

async function checkAsset(id){
  try{ toast("Checking website…"); await api(`/api/assets/${id}/check`,{method:"POST"}); await Promise.all([loadAssets(),loadNotifications(),loadMe()]); toast("Uptime check completed"); }
  catch(err){toast(err.message,"error");}
}
window.checkAsset=checkAsset;
async function removeAsset(id){
  if(!confirm("Remove this monitored asset?")) return;
  try{await api(`/api/assets/${id}`,{method:"DELETE"});await Promise.all([loadAssets(),loadMe()]);toast("Monitor removed");}catch(err){toast(err.message,"error")}
}
window.removeAsset=removeAsset;
async function toggleAsset(id,enabled){
  try{await api(`/api/assets/${id}/enabled`,{method:"PUT",body:JSON.stringify({enabled})});await loadAssets();toast(enabled?"Monitor enabled":"Monitor paused");}catch(err){toast(err.message,"error")}
}
window.toggleAsset=toggleAsset;
async function showUptime(id){
  try{
    const d=await api(`/api/assets/${id}/uptime?limit=30`);
    const recent=d.checks.slice(0,8).map(c=>`<div class="change-item"><strong>${c.online?"Online":"Offline"}</strong><br><span>HTTP: ${escapeHtml(c.http_status ?? "—")} • ${escapeHtml(c.response_ms ?? "—")} ms</span><br><span>${escapeHtml(formatWhen(c.checked_at))}</span></div>`).join("");
    $("compareContent").innerHTML=`<div class="compare-summary"><div><span>Uptime</span><strong>${escapeHtml(d.uptime_percent)}%</strong></div><div><span>Average response</span><strong>${escapeHtml(d.average_response_ms)} ms</strong></div><div><span>Checks</span><strong>${escapeHtml(d.checks.length)}</strong></div></div>${recent || '<div class="no-data">No checks yet.</div>'}`;
    $("compareModal").classList.remove("hidden");
  }catch(err){toast(err.message,"error")}
}
window.showUptime=showUptime;

async function loadNotifications(){
  try{
    const d=await api("/api/notifications");
    const unread=d.items.filter(x=>!x.is_read).length;
    const count=$("notificationCount");
    if(count){count.textContent=String(unread);count.classList.toggle("hidden",unread===0)}
    const html=d.items.length?d.items.map(n=>`<div class="notification-item ${escapeHtml(n.level)} ${n.is_read?"":"unread"}"><strong>${escapeHtml(n.title)}</strong><p>${escapeHtml(n.message)}</p><small>${escapeHtml(formatWhen(n.created_at))}</small></div>`).join(""):'<div class="no-data">No notifications.</div>';
    if($("notificationList")) $("notificationList").innerHTML=html;
    if($("notificationDrawerList")) $("notificationDrawerList").innerHTML=html;
  }catch{}
}
$("notificationButton")?.addEventListener("click",()=>{$("notificationDrawer").classList.add("open");$("notificationDrawer").setAttribute("aria-hidden","false")});
$("closeNotifications")?.addEventListener("click",()=>{$("notificationDrawer").classList.remove("open");$("notificationDrawer").setAttribute("aria-hidden","true")});
$("markNotificationsRead")?.addEventListener("click",async()=>{try{await api("/api/notifications/read",{method:"POST"});await Promise.all([loadNotifications(),loadMe()]);toast("Notifications marked as read")}catch(err){toast(err.message,"error")}});

$("emailHeaderForm")?.addEventListener("submit",async e=>{
  e.preventDefault();const box=$("emailHeaderResult");box.className="mini-result";box.innerHTML="Analyzing authentication headers…";
  try{
    const d=await api("/api/email-headers",{method:"POST",body:JSON.stringify({headers:$("emailHeadersInput").value})});
    box.innerHTML=`<div style="display:flex;justify-content:space-between;align-items:center"><strong>Header risk ${d.risk_score}/100</strong>${riskPill(d.risk)}</div><div class="domain-list"><div><b>SPF</b><span>${escapeHtml(d.spf)}</span></div><div><b>DKIM</b><span>${escapeHtml(d.dkim)}</span></div><div><b>DMARC</b><span>${escapeHtml(d.dmarc)}</span></div><div><b>Received hops</b><span>${escapeHtml(d.received_hops)}</span></div></div><ul>${d.findings.map(x=>`<li>${escapeHtml(x)}</li>`).join("")}</ul>`;
  }catch(err){box.innerHTML=`<span class="pill high">error</span> ${escapeHtml(err.message)}`}
});

$("fileScanForm")?.addEventListener("submit",async e=>{
  e.preventDefault();const box=$("fileScanResult"),file=$("fileInput").files[0];if(!file)return;
  box.className="mini-result";box.innerHTML="Calculating hashes and inspecting file…";
  try{
    const fd=new FormData();fd.append("file",file);
    const d=await api("/api/file-scan",{method:"POST",body:fd});
    box.innerHTML=`<div style="display:flex;justify-content:space-between;align-items:center"><strong>${escapeHtml(d.filename)}</strong>${riskPill(d.risk)}</div><p>Size: ${escapeHtml(d.size_bytes)} bytes • Entropy: ${escapeHtml(d.entropy)}</p><div><b>SHA-256</b><div class="hash-value">${escapeHtml(d.sha256)}</div></div><div style="margin-top:8px"><b>MD5 fingerprint</b><div class="hash-value">${escapeHtml(d.md5)}</div></div><ul>${d.indicators.map(x=>`<li>${escapeHtml(x)}</li>`).join("")}</ul>`;
  }catch(err){box.innerHTML=`<span class="pill high">error</span> ${escapeHtml(err.message)}`}
});

async function showRemediation(scanId){
  const modal=$("remediationModal"),box=$("remediationContent");modal.classList.remove("hidden");box.innerHTML="Building recommendations…";
  try{
    const d=await api(`/api/remediation/${scanId}`);
    box.innerHTML=`<div class="compare-summary"><div><span>Security score</span><strong>${d.score}/100</strong></div><div><span>Risk</span><strong>${escapeHtml(String(d.risk).toUpperCase())}</strong></div><div><span>Actions</span><strong>${d.recommendations.length}</strong></div></div>`+(d.recommendations.length?d.recommendations.map(r=>`<div class="remediation-item"><span class="pill ${escapeHtml(r.severity)} sev">${escapeHtml(r.severity.toUpperCase())}</span><strong>${escapeHtml(r.finding)}</strong><p><b>Evidence:</b> ${escapeHtml(r.evidence)}</p><p>${escapeHtml(r.recommendation)}</p></div>`).join(""):`<div class="no-data">${escapeHtml(d.summary)}</div>`);
  }catch(err){box.innerHTML=`<div class="no-data">${escapeHtml(err.message)}</div>`}
}
window.showRemediation=showRemediation;
$("closeRemediation")?.addEventListener("click",()=>$("remediationModal").classList.add("hidden"));
$("remediationModal")?.addEventListener("click",e=>{if(e.target===$("remediationModal"))$("remediationModal").classList.add("hidden")});

// Refresh live-monitoring data while the dashboard is open.
setInterval(()=>{if(authToken){loadAssets();loadNotifications();}},30000);
