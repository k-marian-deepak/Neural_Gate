from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query


def build_api_router(get_state):
    router = APIRouter(prefix="/api")

    @router.get("/logs")
    async def get_logs(
        attack_type: str | None = Query(default=None, alias="type"),
        severity: str | None = Query(default=None, alias="sev"),
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> list[dict[str, Any]]:
        state = get_state()
        return state.siem.get_logs(attack_type=attack_type, severity=severity, limit=limit, offset=offset)

    @router.get("/stats")
    async def get_stats() -> dict[str, Any]:
        return get_state().siem.stats()

    @router.get("/blocklist")
    async def get_blocklist() -> dict[str, Any]:
        state = get_state()
        return {"blocked_ips": state.siem.list_blocked_ips()}

    @router.delete("/blocklist/{ip}")
    async def unblock_ip(ip: str) -> dict[str, Any]:
        state = get_state()
        removed = state.siem.unblock_ip(ip)
        return {"ip": ip, "removed": removed}

    @router.post("/killswitch")
    async def enable_killswitch() -> dict[str, Any]:
        state = get_state()
        state.siem.set_kill_switch(True)
        payload = {
            "event": "kill_switch",
            "action": "ENABLED",
            "message": "Kill switch enabled",
        }
        state.siem.add_event(payload)
        await state.ws.broadcast(payload)
        return {"enabled": True}

    @router.delete("/killswitch")
    async def disable_killswitch() -> dict[str, Any]:
        state = get_state()
        state.siem.set_kill_switch(False)
        payload = {
            "event": "kill_switch",
            "action": "DISABLED",
            "message": "Kill switch disabled",
        }
        state.siem.add_event(payload)
        await state.ws.broadcast(payload)
        return {"enabled": False}

    @router.get("/agents")
    async def get_agent_scores() -> dict[str, Any]:
        return get_state().last_agent_scores

    return router
