import asyncio
import json
import os
from contextlib import asynccontextmanager
from typing import Dict, Any, Set
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from shadowpot.logger import EventLogger

def create_dashboard_app(event_logger: EventLogger, config: Dict[str, Any]) -> FastAPI:
    active_queues: Set[asyncio.Queue] = set()
    main_loop: list = [None]

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        main_loop[0] = asyncio.get_running_loop()
        yield

    app = FastAPI(title="ShadowPot Threat Dashboard", version="1.0.0", lifespan=lifespan)

    def on_new_event(event: Dict[str, Any]):
        loop = main_loop[0]
        if loop and loop.is_running():
            for q in list(active_queues):
                try:
                    loop.call_soon_threadsafe(q.put_nowait, event)
                except Exception:
                    pass

    event_logger.register_listener(on_new_event)

    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        index_path = os.path.join(static_dir, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return f.read()
        return "<h1>ShadowPot Dashboard</h1><p>static/index.html missing.</p>"

    @app.get("/api/stats")
    async def get_stats():
        return event_logger.get_stats()

    @app.get("/api/events")
    async def get_events(limit: int = 50):
        return event_logger.get_recent_events(limit=limit)

    @app.get("/api/payloads")
    async def get_payloads(limit: int = 20):
        return event_logger.get_payloads(limit=limit)

    @app.get("/api/stream")
    async def event_stream(request: Request):
        q = asyncio.Queue()
        active_queues.add(q)

        async def generator():
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(q.get(), timeout=15.0)
                        yield f"data: {json.dumps(event)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                active_queues.discard(q)

        return StreamingResponse(generator(), media_type="text/event-stream")

    return app
