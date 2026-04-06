from fastapi import WebSocket

class WSManager:
    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket):
        self.clients.discard(ws)

    async def broadcast(self, payload: dict):
        dead = []
        for c in list(self.clients):
            try:
                await c.send_json(payload)
            except Exception:
                dead.append(c)
        for d in dead:
            self.disconnect(d)

manager = WSManager()
