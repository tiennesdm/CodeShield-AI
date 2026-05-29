import json
from typing import Any, Dict, List
from fastapi import WebSocket
from utils.logger import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    """Manages WebSocket connections for real-time scan updates."""

    def __init__(self) -> None:
        # scan_id -> list of connected websockets
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        """Accept connection and register it for the scan_id."""
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
        logger.debug("WebSocket connected for scan %s. Total connections: %d", scan_id, len(self.active_connections[scan_id]))

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        """Remove a disconnected websocket."""
        if scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)
                logger.debug("WebSocket disconnected for scan %s", scan_id)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast_to_scan(self, scan_id: str, message: Dict[str, Any]) -> None:
        """Send a JSON payload to all connections listening to a specific scan_id."""
        if scan_id not in self.active_connections:
            return

        dead_connections: List[WebSocket] = []
        payload = json.dumps(message)

        for connection in self.active_connections[scan_id]:
            try:
                await connection.send_text(payload)
            except Exception as e:
                logger.debug("Failed to send message to connection in scan %s: %s", scan_id, e)
                dead_connections.append(connection)

        # Cleanup any closed/dead connections discovered during broadcast
        for dead in dead_connections:
            self.disconnect(scan_id, dead)


ws_manager = ConnectionManager()
