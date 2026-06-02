"""Dashboard API, GitHub login, API keys, and realtime feed for KYC operations."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Body, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.services.dashboard_auth_store import get_dashboard_auth_store
from app.services.dashboard_events import dashboard_events
from app.services.kyc_dashboard_store import get_kyc_dashboard_store

router = APIRouter()

OAUTH_STATE_COOKIE = "simba_github_oauth_state"


class ManualDecisionRequest(BaseModel):
    decision: str = Field(..., description="APPROVED, REJECTED ou MANUAL_REVIEW")
    reason: Optional[str] = Field(None, description="Raison de la decision humaine")
    reviewer_id: Optional[str] = Field(None, description="Identifiant de l'operateur")


class CreateAPIKeyRequest(BaseModel):
    name: str = Field(default="Production", min_length=1, max_length=80)


def _dashboard_origin(request: Request) -> str:
    if settings.DASHBOARD_BASE_URL:
        return settings.DASHBOARD_BASE_URL.rstrip("/")
    return str(request.base_url).rstrip("/")


def _github_oauth_ready() -> bool:
    return bool(settings.GITHUB_OAUTH_CLIENT_ID and settings.GITHUB_OAUTH_CLIENT_SECRET)


def _current_dashboard_user(request: Request) -> Optional[dict]:
    token = request.cookies.get(settings.DASHBOARD_COOKIE_NAME)
    return get_dashboard_auth_store().get_user_by_session_token(token)


def _require_dashboard_user(request: Request) -> dict:
    user = _current_dashboard_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Session dashboard requise")
    return user


def _session_cookie_kwargs(request: Request) -> dict:
    return {
        "httponly": True,
        "secure": request.url.scheme == "https",
        "samesite": "lax",
        "path": "/",
    }


def _select_primary_email(profile: dict, emails: list[dict]) -> Optional[str]:
    if profile.get("email"):
        return profile["email"]
    primary = next((item for item in emails if item.get("primary") and item.get("verified")), None)
    if primary:
        return primary.get("email")
    verified = next((item for item in emails if item.get("verified")), None)
    return verified.get("email") if verified else None


DASHBOARD_HTML = r"""
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Simba KYC Portal</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #F5F4EF;
      --surface: #ffffff;
      --surface-2: #FAFAF7;
      --text: #123D35;
      --body: #1F2937;
      --muted: #667085;
      --line: #D7D5CC;
      --green: #006B55;
      --dark: #111827;
      --warn: #9A5B00;
      --bad: #B42318;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--body);
    }
    a { color: inherit; text-decoration: none; }
    h1, h2, h3 { color: var(--text); margin: 0; letter-spacing: 0; }
    h1 { font-size: clamp(36px, 6vw, 72px); line-height: .98; font-weight: 900; max-width: 880px; }
    h2 { font-size: 22px; font-weight: 850; }
    h3 { font-size: 15px; font-weight: 850; }
    p { color: var(--muted); line-height: 1.65; margin: 0; }
    button, input, select, textarea {
      font: inherit;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      color: var(--dark);
    }
    button {
      cursor: pointer;
      padding: 10px 13px;
      font-weight: 750;
    }
    button.primary, a.primary { background: var(--green); color: #fff; border-color: var(--green); }
    button.danger { background: var(--bad); color: #fff; border-color: var(--bad); }
    button.ghost { background: transparent; }
    button:disabled { cursor: not-allowed; opacity: .55; }
    input, select, textarea { padding: 10px 11px; min-height: 40px; }
    .topbar {
      position: sticky;
      top: 0;
      z-index: 10;
      background: rgba(245, 244, 239, .95);
      border-bottom: 1px solid var(--line);
      backdrop-filter: blur(12px);
    }
    .topbar-inner {
      max-width: 1180px;
      margin: 0 auto;
      padding: 14px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--text);
      font-weight: 900;
    }
    .brand-mark {
      width: 34px;
      height: 34px;
      border-radius: 8px;
      background: var(--text);
      color: #fff;
      display: grid;
      place-items: center;
      font-weight: 900;
    }
    .nav-actions { display: flex; gap: 9px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 4px 9px;
      border: 1px solid var(--line);
      border-radius: 999px;
      color: var(--muted);
      background: #fff;
      font-size: 12px;
      font-weight: 760;
    }
    .hero {
      max-width: 1180px;
      margin: 0 auto;
      padding: 64px 20px 42px;
      display: grid;
      gap: 28px;
    }
    .hero-copy {
      display: grid;
      gap: 22px;
      max-width: 880px;
    }
    .hero-copy p { max-width: 740px; font-size: 18px; color: #475467; }
    .hero-actions { display: flex; gap: 12px; flex-wrap: wrap; }
    .hero-actions a, .hero-actions button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      padding: 0 16px;
      border-radius: 8px;
      border: 1px solid var(--line);
      font-weight: 800;
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }
    .metric, .panel, .card {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 12px 30px rgba(17, 24, 39, .05);
    }
    .metric { padding: 18px; }
    .metric strong { display: block; color: var(--text); font-size: 28px; font-weight: 900; }
    .metric span { color: var(--muted); font-size: 13px; }
    .workspace {
      max-width: 1380px;
      margin: 0 auto;
      padding: 22px 18px 36px;
      display: none;
      grid-template-columns: minmax(340px, .82fr) minmax(520px, 1.18fr);
      gap: 16px;
    }
    body.authenticated .landing { display: none; }
    body.authenticated .workspace { display: grid; }
    .panel { overflow: hidden; }
    .panel-head, .toolbar, .detail-head, .decision-bar, .key-form {
      padding: 14px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .panel-head { justify-content: space-between; }
    .toolbar input { flex: 1; min-width: 170px; }
    .tabs { display: flex; gap: 8px; }
    .tab.active { background: var(--text); color: #fff; border-color: var(--text); }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      text-align: left;
      padding: 11px 12px;
      border-bottom: 1px solid #eceae4;
      vertical-align: top;
      font-size: 13px;
    }
    th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .12em; }
    tr[data-id] { cursor: pointer; }
    tr[data-id]:hover { background: var(--surface-2); }
    .status {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 850;
      background: #E9F5F1;
      color: var(--green);
    }
    .status.REJECTED, .status.ERROR { background: #FEE4E2; color: var(--bad); }
    .status.MANUAL_REVIEW, .status.PROCESSING { background: #FFF3D6; color: var(--warn); }
    .muted { color: var(--muted); }
    .score { font-size: 22px; font-weight: 900; color: var(--text); }
    .detail-body { padding: 14px; display: grid; gap: 14px; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .box { border: 1px solid #eceae4; border-radius: 8px; padding: 12px; background: #fff; }
    .assets { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
    .asset img { width: 100%; aspect-ratio: 4 / 3; object-fit: cover; border-radius: 6px; border: 1px solid var(--line); background: #f3f4f6; }
    pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 12px;
      line-height: 1.45;
      color: #344054;
      max-height: 320px;
      overflow: auto;
    }
    .empty { padding: 30px 14px; color: var(--muted); text-align: center; }
    .key-form input { flex: 1; min-width: 180px; }
    .key-reveal {
      display: none;
      margin: 14px;
      padding: 12px;
      background: #ECFDF3;
      border: 1px solid #ABEFC6;
      border-radius: 8px;
    }
    .key-reveal code { display: block; word-break: break-all; margin-top: 8px; color: var(--text); font-weight: 800; }
    .screen { display: none; }
    .screen.active { display: block; }
    .avatar { width: 32px; height: 32px; border-radius: 50%; object-fit: cover; border: 1px solid var(--line); }
    .config-warning {
      max-width: 1180px;
      margin: 0 auto 20px;
      padding: 0 20px;
    }
    .config-warning .box { border-color: #FEC84B; background: #FFFAEB; }
    @media (max-width: 980px) {
      .workspace { grid-template-columns: 1fr; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 640px) {
      h1 { font-size: 38px; }
      .topbar-inner { align-items: flex-start; flex-direction: column; }
      .nav-actions { justify-content: flex-start; }
      .hero { padding-top: 36px; }
      .metrics { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <a class="brand" href="/dashboard" aria-label="Simba KYC">
        <span class="brand-mark">S</span>
        <span>Simba KYC</span>
      </a>
      <div class="nav-actions" id="navActions">
        <span class="pill" id="connection">Portail public</span>
        <a class="primary" id="loginLink" href="/dashboard/auth/github">Connexion GitHub</a>
      </div>
    </div>
  </header>

  <div class="landing">
    <section class="hero">
      <div class="hero-copy">
        <span class="pill">Microservice KYC autonome</span>
        <h1>Validez les identites, suivez les scores IA et generez vos cles API au meme endroit.</h1>
        <p>Simba centralise OCR, QR, MRZ, liveness AWS Rekognition, detection de fraude et revue manuelle. Les applications clientes consomment le service via API, pendant que l'equipe suit les demandes KYC dans ce portail.</p>
        <div class="hero-actions">
          <a class="primary" href="/dashboard/auth/github" id="heroLogin">Se connecter avec GitHub</a>
          <a href="/ready">Verifier le service</a>
        </div>
      </div>
      <div class="metrics">
        <div class="metric"><strong>OCR</strong><span>Extraction documentaire par Groq multimodal</span></div>
        <div class="metric"><strong>QR/MRZ</strong><span>Controle croise des sources documentaires</span></div>
        <div class="metric"><strong>AWS</strong><span>Liveness et comparaison visage</span></div>
        <div class="metric"><strong>API</strong><span>Cles d'acces creees depuis le portail</span></div>
      </div>
    </section>
    <div class="config-warning" id="oauthWarning" hidden>
      <div class="box">
        <h3>Connexion GitHub a configurer</h3>
        <p>Ajoutez <strong>GITHUB_OAUTH_CLIENT_ID</strong>, <strong>GITHUB_OAUTH_CLIENT_SECRET</strong> et <strong>DASHBOARD_BASE_URL</strong> dans l'environnement Simba pour activer la creation de compte.</p>
      </div>
    </div>
  </div>

  <main class="workspace">
    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>Operations</h2>
          <p id="userLabel">Session dashboard</p>
        </div>
        <div class="tabs">
          <button class="tab active" data-screen="kycScreen">KYC</button>
          <button class="tab" data-screen="keysScreen">Cles API</button>
        </div>
      </div>
      <div class="screen active" id="kycScreen">
        <div class="toolbar">
          <input id="searchUser" placeholder="Filtrer par user_id" />
          <select id="statusFilter">
            <option value="">Tous statuts</option>
            <option>PROCESSING</option>
            <option>APPROVED</option>
            <option>MANUAL_REVIEW</option>
            <option>REJECTED</option>
            <option>ERROR</option>
          </select>
          <button id="refresh">Rafraichir</button>
        </div>
        <div id="list"><div class="empty">Chargement des demandes KYC.</div></div>
      </div>
      <div class="screen" id="keysScreen">
        <div class="key-form">
          <input id="keyName" placeholder="Nom de la cle: production, staging, mobile..." />
          <button class="primary" id="createKey">Creer une cle</button>
        </div>
        <div class="key-reveal" id="keyReveal">
          <strong>Nouvelle cle API</strong>
          <p>Copiez-la maintenant. Elle ne sera plus affichee apres fermeture.</p>
          <code id="newApiKey"></code>
        </div>
        <div id="keysList"><div class="empty">Chargement des cles API.</div></div>
      </div>
    </section>
    <section class="panel">
      <div class="detail-head">
        <h2 id="detailTitle">Selectionner une demande</h2>
        <span class="muted" id="detailMeta"></span>
      </div>
      <div id="detail" class="detail-body">
        <div class="empty">Les details KYC, assets, score IA et suggestions apparaitront ici.</div>
      </div>
    </section>
  </main>

  <script>
    const boot = { oauthReady: __OAUTH_READY__ };
    const state = { user: null, ws: null, selected: null };

    function statusClass(value) { return `status ${value || ""}`; }
    function formatDate(value) { return value ? new Date(value).toLocaleString() : "-"; }
    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]));
    }
    async function api(path, options = {}) {
      const response = await fetch(path, {
        ...options,
        headers: { "Content-Type": "application/json", ...(options.headers || {}) }
      });
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      return response.json();
    }

    async function loadMe() {
      if (!boot.oauthReady) document.querySelector("#oauthWarning").hidden = false;
      try {
        const data = await api("/api/v1/dashboard/me");
        state.user = data.user;
        document.body.classList.add("authenticated");
        document.querySelector("#connection").textContent = "Temps reel en attente";
        document.querySelector("#userLabel").textContent = `${state.user.name || state.user.github_login} · @${state.user.github_login}`;
        document.querySelector("#navActions").innerHTML = `
          ${state.user.avatar_url ? `<img class="avatar" src="${state.user.avatar_url}" alt="" />` : ""}
          <span class="pill">@${escapeHtml(state.user.github_login)}</span>
          <form method="post" action="/dashboard/logout"><button class="ghost" type="submit">Deconnexion</button></form>
        `;
        await Promise.all([loadList(), loadKeys()]);
        connectWs();
      } catch (error) {
        document.body.classList.remove("authenticated");
        if (!boot.oauthReady) {
          document.querySelector("#loginLink").setAttribute("aria-disabled", "true");
          document.querySelector("#heroLogin").setAttribute("aria-disabled", "true");
        }
      }
    }

    async function loadList() {
      const params = new URLSearchParams();
      const status = document.querySelector("#statusFilter").value;
      const user = document.querySelector("#searchUser").value.trim();
      if (status) params.set("status", status);
      if (user) params.set("user_id", user);
      const rows = await api(`/api/v1/dashboard/requests?${params.toString()}`);
      const html = rows.length ? `
        <table>
          <thead><tr><th>Date</th><th>User</th><th>Statut</th><th>Score</th></tr></thead>
          <tbody>
            ${rows.map(row => `
              <tr data-id="${escapeHtml(row.id)}">
                <td>${formatDate(row.created_at)}</td>
                <td><strong>${escapeHtml(row.user_id)}</strong><br><span class="muted">${escapeHtml(row.id.slice(0, 10))}</span></td>
                <td><span class="${statusClass(row.status)}">${escapeHtml(row.status)}</span><br><span class="muted">${escapeHtml(row.recommendation || "")}</span></td>
                <td class="score">${row.kyc_score ?? "-"}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>` : `<div class="empty">Aucune demande KYC.</div>`;
      document.querySelector("#list").innerHTML = html;
      document.querySelectorAll("tr[data-id]").forEach(row => row.addEventListener("click", () => loadDetail(row.dataset.id)));
    }

    async function assetObjectUrl(asset) {
      const response = await fetch(asset.url);
      if (!response.ok) return "";
      return URL.createObjectURL(await response.blob());
    }

    async function loadDetail(id) {
      state.selected = id;
      const detail = await api(`/api/v1/dashboard/requests/${id}`);
      document.querySelector("#detailTitle").textContent = detail.user_id;
      document.querySelector("#detailMeta").innerHTML = `<span class="${statusClass(detail.status)}">${escapeHtml(detail.status)}</span>`;
      const assetBlocks = await Promise.all((detail.assets || []).map(async asset => {
        const url = await assetObjectUrl(asset);
        return `<div class="asset box"><h3>${escapeHtml(asset.kind)}</h3>${url ? `<img src="${url}" alt="${escapeHtml(asset.kind)}" />` : ""}<div class="muted">${escapeHtml(asset.filename)}</div></div>`;
      }));

      document.querySelector("#detail").innerHTML = `
        <div class="grid">
          <div class="box"><h3>Decision</h3><div class="score">${detail.kyc_score ?? "-"}</div><p>${escapeHtml(detail.recommendation || "-")}</p><p>${escapeHtml(detail.reason || detail.error || "")}</p></div>
          <div class="box"><h3>Liveness AWS</h3><pre>${escapeHtml(JSON.stringify(detail.liveness || {}, null, 2))}</pre></div>
        </div>
        <div class="box"><h3>Assets uploades</h3><div class="assets">${assetBlocks.join("") || "<span class='muted'>Aucun asset</span>"}</div></div>
        <div class="box"><h3>Suggestions IA</h3><ul>${(detail.suggestions || []).map(item => `<li>${escapeHtml(item)}</li>`).join("") || "<li>Aucune suggestion</li>"}</ul></div>
        <div class="grid">
          <div class="box"><h3>Identite extraite</h3><pre>${escapeHtml(JSON.stringify(detail.kyc_data || {}, null, 2))}</pre></div>
          <div class="box"><h3>Fraude / criteres</h3><pre>${escapeHtml(JSON.stringify(detail.fraud_indicators || {}, null, 2))}</pre></div>
        </div>
        <div class="box"><h3>Sources QR / MRZ</h3><pre>${escapeHtml(JSON.stringify({ qr_data: detail.qr_data, mrz_data: detail.mrz_data, source_checks: detail.source_checks }, null, 2))}</pre></div>
        <div class="decision-bar">
          <button class="primary" data-decision="APPROVED">Approuver</button>
          <button data-decision="MANUAL_REVIEW">Maintenir revue</button>
          <button class="danger" data-decision="REJECTED">Rejeter</button>
          <textarea id="decisionReason" placeholder="Raison de decision manuelle" rows="2"></textarea>
        </div>
      `;
      document.querySelectorAll("button[data-decision]").forEach(button => {
        button.addEventListener("click", () => sendDecision(id, button.dataset.decision));
      });
    }

    async function sendDecision(id, decision) {
      const reason = document.querySelector("#decisionReason")?.value || "";
      await api(`/api/v1/dashboard/requests/${id}/decision`, {
        method: "POST",
        body: JSON.stringify({ decision, reason, reviewer_id: state.user?.github_login || "dashboard" })
      });
      await loadList();
      await loadDetail(id);
    }

    async function loadKeys() {
      const rows = await api("/api/v1/dashboard/api-keys");
      const html = rows.length ? `
        <table>
          <thead><tr><th>Nom</th><th>Prefixe</th><th>Derniere utilisation</th><th>Etat</th><th></th></tr></thead>
          <tbody>
            ${rows.map(row => `
              <tr>
                <td><strong>${escapeHtml(row.name)}</strong><br><span class="muted">${formatDate(row.created_at)}</span></td>
                <td><code>${escapeHtml(row.key_prefix)}...</code></td>
                <td>${formatDate(row.last_used_at)}</td>
                <td>${row.revoked_at ? "<span class='status REJECTED'>Revoquee</span>" : "<span class='status APPROVED'>Active</span>"}</td>
                <td>${row.revoked_at ? "" : `<button class="danger" data-revoke="${escapeHtml(row.id)}">Revoquer</button>`}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>` : `<div class="empty">Aucune cle API creee.</div>`;
      document.querySelector("#keysList").innerHTML = html;
      document.querySelectorAll("button[data-revoke]").forEach(button => button.addEventListener("click", async () => {
        await api(`/api/v1/dashboard/api-keys/${button.dataset.revoke}`, { method: "DELETE" });
        await loadKeys();
      }));
    }

    async function createKey() {
      const name = document.querySelector("#keyName").value.trim() || "Production";
      const created = await api("/api/v1/dashboard/api-keys", { method: "POST", body: JSON.stringify({ name }) });
      document.querySelector("#newApiKey").textContent = created.api_key;
      document.querySelector("#keyReveal").style.display = "block";
      document.querySelector("#keyName").value = "";
      await loadKeys();
    }

    function connectWs() {
      if (state.ws) state.ws.close();
      const proto = location.protocol === "https:" ? "wss" : "ws";
      state.ws = new WebSocket(`${proto}://${location.host}/api/v1/dashboard/ws`);
      state.ws.onopen = () => document.querySelector("#connection").textContent = "Temps reel connecte";
      state.ws.onclose = () => document.querySelector("#connection").textContent = "Temps reel deconnecte";
      state.ws.onmessage = async event => {
        const payload = JSON.parse(event.data);
        if (payload.type && payload.type !== "connected") {
          await loadList();
          if (state.selected && payload.request_id === state.selected) await loadDetail(state.selected);
        }
      };
    }

    document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(item => item.classList.remove("active"));
      document.querySelectorAll(".screen").forEach(item => item.classList.remove("active"));
      button.classList.add("active");
      document.querySelector(`#${button.dataset.screen}`).classList.add("active");
    }));
    document.querySelector("#refresh").addEventListener("click", loadList);
    document.querySelector("#statusFilter").addEventListener("change", loadList);
    document.querySelector("#searchUser").addEventListener("input", () => setTimeout(loadList, 100));
    document.querySelector("#createKey").addEventListener("click", createKey);
    loadMe();
  </script>
</body>
</html>
"""


@router.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
async def dashboard_home() -> HTMLResponse:
    html = DASHBOARD_HTML.replace("__OAUTH_READY__", "true" if _github_oauth_ready() else "false")
    return HTMLResponse(html)


@router.get("/dashboard/auth/github", tags=["Dashboard Auth"])
async def github_login(request: Request) -> RedirectResponse:
    if not _github_oauth_ready():
        return RedirectResponse("/dashboard", status_code=303)

    state = secrets.token_urlsafe(32)
    callback_url = f"{_dashboard_origin(request)}/dashboard/auth/github/callback"
    params = urlencode(
        {
            "client_id": settings.GITHUB_OAUTH_CLIENT_ID,
            "redirect_uri": callback_url,
            "scope": "read:user user:email",
            "state": state,
        }
    )
    response = RedirectResponse(f"https://github.com/login/oauth/authorize?{params}", status_code=303)
    response.set_cookie(OAUTH_STATE_COOKIE, state, max_age=600, **_session_cookie_kwargs(request))
    return response


@router.get("/dashboard/auth/github/callback", tags=["Dashboard Auth"])
async def github_callback(request: Request, code: str = Query(""), state: str = Query("")) -> RedirectResponse:
    expected_state = request.cookies.get(OAUTH_STATE_COOKIE)
    if not _github_oauth_ready() or not code or not state or state != expected_state:
        return RedirectResponse("/dashboard", status_code=303)

    callback_url = f"{_dashboard_origin(request)}/dashboard/auth/github/callback"
    async with httpx.AsyncClient(timeout=15) as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.GITHUB_OAUTH_CLIENT_ID,
                "client_secret": settings.GITHUB_OAUTH_CLIENT_SECRET,
                "code": code,
                "redirect_uri": callback_url,
                "state": state,
            },
        )
        token_response.raise_for_status()
        token_payload = token_response.json()
        access_token = token_payload.get("access_token")
        if not access_token:
            return RedirectResponse("/dashboard", status_code=303)

        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"}
        profile_response = await client.get("https://api.github.com/user", headers=headers)
        profile_response.raise_for_status()
        emails_response = await client.get("https://api.github.com/user/emails", headers=headers)
        emails = emails_response.json() if emails_response.status_code == 200 else []

    profile = profile_response.json()
    auth_store = get_dashboard_auth_store()
    user = auth_store.upsert_github_user(profile, _select_primary_email(profile, emails))
    session_token = auth_store.create_session(user["id"])
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(settings.DASHBOARD_COOKIE_NAME, session_token, max_age=14 * 24 * 3600, **_session_cookie_kwargs(request))
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/")
    return response


@router.post("/dashboard/logout", tags=["Dashboard Auth"])
async def dashboard_logout(request: Request) -> RedirectResponse:
    get_dashboard_auth_store().revoke_session(request.cookies.get(settings.DASHBOARD_COOKIE_NAME))
    response = RedirectResponse("/dashboard", status_code=303)
    response.delete_cookie(settings.DASHBOARD_COOKIE_NAME, path="/")
    return response


@router.get("/api/v1/dashboard/me", tags=["Dashboard Auth"])
async def dashboard_me(request: Request) -> dict:
    return {"user": _require_dashboard_user(request), "oauth_ready": _github_oauth_ready()}


@router.get("/api/v1/dashboard/api-keys", tags=["Dashboard Auth"])
async def list_api_keys(request: Request) -> list[dict]:
    user = _require_dashboard_user(request)
    return get_dashboard_auth_store().list_api_keys(user["id"])


@router.post("/api/v1/dashboard/api-keys", tags=["Dashboard Auth"])
async def create_api_key(request: Request, payload: CreateAPIKeyRequest = Body(...)) -> dict:
    user = _require_dashboard_user(request)
    return get_dashboard_auth_store().create_api_key(user["id"], payload.name)


@router.delete("/api/v1/dashboard/api-keys/{key_id}", tags=["Dashboard Auth"])
async def revoke_api_key(request: Request, key_id: str) -> dict:
    user = _require_dashboard_user(request)
    revoked = get_dashboard_auth_store().revoke_api_key(user_id=user["id"], key_id=key_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"revoked": True}


@router.get("/api/v1/dashboard/requests", tags=["Dashboard"])
async def list_kyc_requests(
    status: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[dict]:
    store = get_kyc_dashboard_store()
    return store.list_requests(status=status, user_id=user_id, limit=limit, offset=offset)


@router.get("/api/v1/dashboard/requests/{request_id}", tags=["Dashboard"])
async def get_kyc_request(request_id: str) -> dict:
    store = get_kyc_dashboard_store()
    detail = store.get_request(request_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="KYC request not found")
    return detail


@router.post("/api/v1/dashboard/requests/{request_id}/decision", tags=["Dashboard"])
async def apply_manual_decision(request_id: str, payload: ManualDecisionRequest) -> dict:
    store = get_kyc_dashboard_store()
    try:
        detail = store.apply_manual_decision(
            request_id=request_id,
            decision=payload.decision,
            reason=payload.reason,
            reviewer_id=payload.reviewer_id,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="KYC request not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    event = store.add_event(
        request_id=request_id,
        event_type="manual_decision",
        payload={
            "status": detail["status"],
            "decision": detail["decision"],
            "review_reason": detail.get("review_reason"),
            "reviewer_id": detail.get("reviewer_id"),
        },
    )
    await dashboard_events.broadcast(event)
    return detail


@router.get("/api/v1/dashboard/assets/{asset_id}", tags=["Dashboard"])
async def get_kyc_asset(asset_id: str) -> FileResponse:
    store = get_kyc_dashboard_store()
    asset = store.get_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    storage_path = Path(asset["storage_path"])
    if not storage_path.exists() or not storage_path.is_file():
        raise HTTPException(status_code=404, detail="Asset file not found")

    return FileResponse(
        storage_path,
        media_type=asset["content_type"],
        filename=asset["filename"],
    )


@router.websocket("/api/v1/dashboard/ws")
async def dashboard_ws(websocket: WebSocket) -> None:
    api_key = websocket.query_params.get("api_key")
    session_token = websocket.cookies.get(settings.DASHBOARD_COOKIE_NAME)
    request_id = websocket.query_params.get("request_id")

    if not settings.ALLOW_ANONYMOUS:
        auth_store = get_dashboard_auth_store()
        has_session = auth_store.get_user_by_session_token(session_token) is not None
        has_api_key = auth_store.validate_api_key(api_key)
        if not has_session and not has_api_key:
            await websocket.close(code=1008)
            return

    await dashboard_events.connect(websocket, request_id=request_id)
    await websocket.send_json({"type": "connected", "request_id": request_id})
    try:
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        dashboard_events.disconnect(websocket)
