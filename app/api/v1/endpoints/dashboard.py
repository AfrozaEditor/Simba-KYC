"""Dashboard API and realtime feed for KYC operations."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.services.dashboard_events import dashboard_events
from app.services.kyc_dashboard_store import get_kyc_dashboard_store

router = APIRouter()


class ManualDecisionRequest(BaseModel):
    decision: str = Field(..., description="APPROVED, REJECTED ou MANUAL_REVIEW")
    reason: Optional[str] = Field(None, description="Raison de la decision humaine")
    reviewer_id: Optional[str] = Field(None, description="Identifiant de l'operateur")


DASHBOARD_HTML = r"""
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Simba KYC Dashboard</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #F5F4EF;
      --panel: #ffffff;
      --text: #123D35;
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
      color: var(--dark);
    }
    header {
      padding: 18px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    h1, h2, h3 { color: var(--text); margin: 0; }
    h1 { font-size: 22px; font-weight: 800; }
    h2 { font-size: 17px; font-weight: 800; }
    h3 { font-size: 14px; font-weight: 800; margin-bottom: 8px; }
    button, input, select, textarea {
      font: inherit;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      color: var(--dark);
    }
    button {
      cursor: pointer;
      padding: 9px 12px;
      font-weight: 700;
    }
    button.primary { background: var(--green); color: #fff; border-color: var(--green); }
    button.danger { background: var(--bad); color: #fff; border-color: var(--bad); }
    input, select, textarea { padding: 9px 10px; }
    main {
      display: grid;
      grid-template-columns: minmax(360px, 0.9fr) minmax(420px, 1.2fr);
      gap: 18px;
      padding: 18px;
      min-height: calc(100vh - 74px);
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }
    .toolbar, .detail-head, .decision-bar {
      display: flex;
      gap: 10px;
      align-items: center;
      padding: 14px;
      border-bottom: 1px solid var(--line);
      flex-wrap: wrap;
    }
    .toolbar input { min-width: 180px; flex: 1; }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      text-align: left;
      padding: 11px 12px;
      border-bottom: 1px solid #eceae4;
      vertical-align: top;
      font-size: 13px;
    }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    tr { cursor: pointer; }
    tr:hover { background: #faf9f5; }
    .status {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
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
    }
    .empty { padding: 30px 14px; color: var(--muted); text-align: center; }
    .api-key {
      min-width: 280px;
      max-width: 420px;
      flex: 1;
    }
    @media (max-width: 920px) {
      main { grid-template-columns: 1fr; }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Simba KYC Dashboard</h1>
      <div class="muted" id="connection">Connexion non initialisee</div>
    </div>
    <input id="apiKey" class="api-key" type="password" placeholder="X-API-Key" autocomplete="off" />
    <button class="primary" id="saveKey">Connecter</button>
  </header>
  <main>
    <section>
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
      <div id="list"></div>
    </section>
    <section>
      <div class="detail-head">
        <h2 id="detailTitle">Selectionner une demande</h2>
        <span class="muted" id="detailMeta"></span>
      </div>
      <div id="detail" class="detail-body">
        <div class="empty">Les details KYC, assets et suggestions IA apparaitront ici.</div>
      </div>
    </section>
  </main>
  <script>
    const state = { apiKey: localStorage.getItem("simba_kyc_api_key") || "", ws: null, selected: null };
    const apiKeyInput = document.querySelector("#apiKey");
    const connection = document.querySelector("#connection");
    apiKeyInput.value = state.apiKey;

    function headers() {
      return { "X-API-Key": state.apiKey, "Content-Type": "application/json" };
    }

    function statusClass(value) {
      return `status ${value || ""}`;
    }

    async function api(path, options = {}) {
      const response = await fetch(path, { ...options, headers: { ...headers(), ...(options.headers || {}) } });
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      return response.json();
    }

    async function loadList() {
      if (!state.apiKey) return;
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
              <tr data-id="${row.id}">
                <td>${new Date(row.created_at).toLocaleString()}</td>
                <td><strong>${row.user_id}</strong><br><span class="muted">${row.id.slice(0, 10)}</span></td>
                <td><span class="${statusClass(row.status)}">${row.status}</span><br><span class="muted">${row.recommendation || ""}</span></td>
                <td class="score">${row.kyc_score ?? "-"}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>` : `<div class="empty">Aucune demande KYC.</div>`;
      document.querySelector("#list").innerHTML = html;
      document.querySelectorAll("tr[data-id]").forEach(row => row.addEventListener("click", () => loadDetail(row.dataset.id)));
    }

    async function assetObjectUrl(asset) {
      const response = await fetch(asset.url, { headers: { "X-API-Key": state.apiKey } });
      if (!response.ok) return "";
      return URL.createObjectURL(await response.blob());
    }

    async function loadDetail(id) {
      state.selected = id;
      const detail = await api(`/api/v1/dashboard/requests/${id}`);
      document.querySelector("#detailTitle").textContent = `${detail.user_id}`;
      document.querySelector("#detailMeta").innerHTML = `<span class="${statusClass(detail.status)}">${detail.status}</span>`;

      const assetBlocks = await Promise.all((detail.assets || []).map(async asset => {
        const url = await assetObjectUrl(asset);
        return `<div class="asset box"><h3>${asset.kind}</h3>${url ? `<img src="${url}" alt="${asset.kind}" />` : ""}<div class="muted">${asset.filename}</div></div>`;
      }));

      document.querySelector("#detail").innerHTML = `
        <div class="grid">
          <div class="box"><h3>Decision</h3><div class="score">${detail.kyc_score ?? "-"}</div><p>${detail.recommendation || "-"}</p><p>${detail.reason || detail.error || ""}</p></div>
          <div class="box"><h3>Liveness</h3><pre>${JSON.stringify(detail.liveness || {}, null, 2)}</pre></div>
        </div>
        <div class="box"><h3>Assets uploades</h3><div class="assets">${assetBlocks.join("") || "<span class='muted'>Aucun asset</span>"}</div></div>
        <div class="box"><h3>Suggestions IA</h3><ul>${(detail.suggestions || []).map(item => `<li>${item}</li>`).join("") || "<li>Aucune suggestion</li>"}</ul></div>
        <div class="grid">
          <div class="box"><h3>Identite extraite</h3><pre>${JSON.stringify(detail.kyc_data || {}, null, 2)}</pre></div>
          <div class="box"><h3>Fraude / criteres</h3><pre>${JSON.stringify(detail.fraud_indicators || {}, null, 2)}</pre></div>
        </div>
        <div class="box"><h3>Sources QR / MRZ</h3><pre>${JSON.stringify({ qr_data: detail.qr_data, mrz_data: detail.mrz_data, source_checks: detail.source_checks }, null, 2)}</pre></div>
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
        body: JSON.stringify({ decision, reason, reviewer_id: "dashboard" })
      });
      await loadList();
      await loadDetail(id);
    }

    function connectWs() {
      if (!state.apiKey) return;
      if (state.ws) state.ws.close();
      const proto = location.protocol === "https:" ? "wss" : "ws";
      state.ws = new WebSocket(`${proto}://${location.host}/api/v1/dashboard/ws?api_key=${encodeURIComponent(state.apiKey)}`);
      state.ws.onopen = () => connection.textContent = "Temps reel connecte";
      state.ws.onclose = () => connection.textContent = "Temps reel deconnecte";
      state.ws.onmessage = async event => {
        const payload = JSON.parse(event.data);
        if (payload.type && payload.type !== "connected") {
          await loadList();
          if (state.selected && payload.request_id === state.selected) await loadDetail(state.selected);
        }
      };
    }

    document.querySelector("#saveKey").addEventListener("click", async () => {
      state.apiKey = apiKeyInput.value.trim();
      localStorage.setItem("simba_kyc_api_key", state.apiKey);
      connectWs();
      await loadList();
    });
    document.querySelector("#refresh").addEventListener("click", loadList);
    document.querySelector("#statusFilter").addEventListener("change", loadList);
    document.querySelector("#searchUser").addEventListener("input", () => setTimeout(loadList, 100));
    if (state.apiKey) { connectWs(); loadList().catch(console.error); }
  </script>
</body>
</html>
"""


@router.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
async def dashboard_home() -> HTMLResponse:
    return HTMLResponse(DASHBOARD_HTML)


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
    request_id = websocket.query_params.get("request_id")
    if not settings.ALLOW_ANONYMOUS and api_key != settings.API_KEY:
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
