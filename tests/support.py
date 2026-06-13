from typing import Any

import httpx
from fastapi import FastAPI


def client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )


async def request(app: FastAPI, method: str, path: str, *, json: Any = None) -> httpx.Response:
    async with client(app) as test_client:
        return await test_client.request(method, path, json=json)
