from typing import List
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """
        Accepts the incoming websocket connection and adds it to the active pool.
        """
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """
        Removes the connection from the active pool.
        """
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, data: dict) -> None:
        """
        Broadcasts a JSON payload to all registered connections.
        Prunes dead/broken connections automatically.
        """
        dead_sockets = []
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception:
                dead_sockets.append(connection)

        for dead in dead_sockets:
            self.disconnect(dead)
