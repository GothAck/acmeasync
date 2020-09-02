from typing import List, Tuple, Dict

import os
import asyncio
import logging
from aiohttp import web

from acmeasync.certbot2 import CertBot2
from acmeasync.proxyserver import ProxyServer

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

certbot = CertBot2()

app = web.Application()

DOMAINS = os.environ["DOMAINS"].split(",")

PORT = int(os.environ.get("PORT", "8080"))

EMAIL = os.environ["EMAIL"]

PROXIES: List[ProxyServer] = []

ProxyDict = Dict[int, Tuple[str, int]]


def getProxies() -> ProxyDict:
    proxies: ProxyDict = {}
    proxies_str = os.environ.get("PROXIES", "8081:towel.blinkenlights.nl:23")

    for proxy in proxies_str.split(","):
        local_port, remote_host, remote_port = proxy.split(":", 2)
        proxies[int(local_port)] = (remote_host, int(remote_port))

    return proxies


async def setupProxies(proxies: ProxyDict, *domains: str) -> List[asyncio.Task]:
    tasks = []
    for local_port, (remote_host, remote_port) in proxies.items():
        proxy = ProxyServer(local_port, remote_host, remote_port, *domains)
        PROXIES.append(proxy)
        tasks.append(proxy.run())

    return tasks


async def main() -> None:
    app.router.add_get(
        "/.well-known/acme-challenge/{token}", certbot.http01ChallengeHandler
    )

    web_task = asyncio.create_task(web._run_app(app, port=PORT))

    await certbot.begin()
    if not await certbot.loadAccount():
        await certbot.createAccount(EMAIL, True)

    if not await certbot.hasKeyAndCert(*DOMAINS):
        await certbot.orderCert(*DOMAINS)

    renew_task = asyncio.create_task(certbot.renewTask(*DOMAINS))

    proxy_tasks = await setupProxies(getProxies(), *DOMAINS)

    await asyncio.wait([web_task, renew_task] + proxy_tasks)


if __name__ == "__main__":
    asyncio.run(main())
