"""Realtime dashboard event fan-out."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class DashboardEventManager:
    """Small in-process WebSocket hub for KYC status updates."""

    def __init__(self) -> None:
        self._connections: list[tuple[WebSocket, Optional[str]]] = []

    async def connect(self, websocket: WebSocket, request_id: Optional[str] = None) -> None:
        await websocket.accept()
        self._connections.append((websocket, request_id))

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections = [
            (connection, request_id)
            for connection, request_id in self._connections
            if connection is not websocket
        ]

    async def broadcast(self, event: Dict[str, Any]) -> None:
        if not self._connections:
            return

        event_request_id = event.get("request_id")
        stale: list[WebSocket] = []
        for websocket, subscribed_request_id in list(self._connections):
            if subscribed_request_id and subscribed_request_id != event_request_id:
                continue
            try:
                await websocket.send_json(event)
            except Exception as exc:
                logger.debug("Dashboard websocket send failed: %s", exc)
                stale.append(websocket)

        for websocket in stale:
            self.disconnect(websocket)


dashboard_events = DashboardEventManager()
