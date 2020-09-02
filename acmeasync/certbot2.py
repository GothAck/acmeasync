from typing import Dict, cast

import os
from pathlib import Path
import asyncio
import datetime
import logging

from acme import crypto_util
import OpenSSL
from aiohttp import web

from acmeasync.acmele import ACMELE

logger = logging.getLogger(__name__)

DIRECTORY_URL = os.environ.get(
    "DIRECTORY_URL", "https://acme-staging-v02.api.letsencrypt.org/directory"
)


class CertBot2:
    PATH_ACCOUNT_KEY = Path("./account.jwk")
    PATH_CERTS = Path("./certs")

    challenges: Dict[str, str]

    def __init__(self) -> None:
        self.__acme = ACMELE(DIRECTORY_URL)
        self.challenges = {}
        if not self.PATH_CERTS.exists():
            self.PATH_CERTS.mkdir()
            self.PATH_CERTS.chmod(0o700)

    async def begin(self) -> None:
        logger.info("begin")
        await self.__acme.begin()

    async def loadAccount(self) -> bool:
        logger.info("loadAccount")
        return await self.__acme.loadAccount(str(self.PATH_ACCOUNT_KEY))

    async def createAccount(self, email: str, terms_of_service_agreed: bool) -> None:
        logger.info("createAccount")
        await self.__acme.createAccount(email, terms_of_service_agreed)
        await self.__acme.saveAccount(str(self.PATH_ACCOUNT_KEY))

    async def hasKeyAndCert(self, *domains: str) -> bool:
        filename = ",".join(domains)
        key_path = self.PATH_CERTS.joinpath(f"{filename}.key")
        crt_path = self.PATH_CERTS.joinpath(f"{filename}.crt")
        return key_path.exists() and crt_path.exists()

    async def orderCert(self, *domains: str) -> None:
        logger.info("orderCert")
        order = await self.__acme.createOrder(domains)

        logger.info("orderCert order created")

        filename = ",".join(domains)

        challs = []
        for auth in await order.authorizations():
            for chall in await auth.challenges("http-01"):
                self.challenges[chall.data["token"]] = (
                    chall.data["token"] + "." + self.__acme.account_key_thumbprint
                )
                challs.append(await chall.begin())

        if not challs:
            raise Exception("No http-01 challenges")

        logger.info("orderCert awaiting challenges")

        for chall in challs:
            await chall.await_status("valid")

        for chall in challs:
            del self.challenges[chall.data["token"]]

        logger.info("orderCert awaiting order status")

        await order.await_not_status("pending")

        if order.status != "ready":
            raise Exception(f"Order in invalid status {order.status}")

        key_path = self.PATH_CERTS.joinpath(f"{filename}.key")
        crt_path = self.PATH_CERTS.joinpath(f"{filename}.crt")

        key_pem = None
        if key_path.exists():
            logger.info("orderCert loading existing key")
            with key_path.open("rb") as fb:
                key_pem = fb.read()

        if not key_pem:
            logger.info("orderCert creating new key")
            pkey = OpenSSL.crypto.PKey()
            pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
            key_pem = cast(
                bytes, OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
            )
            with key_path.open("wb") as fb:
                key_path.chmod(0o600)
                fb.write(key_pem)

        csr_pem = crypto_util.make_csr(key_pem, domains)

        logger.info("orderCert finalizing order")

        await order.finalize(csr_pem)

        logger.info("orderCert awaiting finalization")

        await order.await_status("valid")

        logger.info("orderCert writing crt")

        with crt_path.open("w") as ft:
            crt_path.chmod(0o600)
            ft.write(await order.get_cert())

    async def http01ChallengeHandler(self, req: web.Request) -> web.Response:
        token = req.match_info["token"]
        logger.info(f"http01ChallengeHandler {token}")
        return web.Response(text=self.challenges.get(token, ""))

    async def getCrt(self, *domains: str) -> OpenSSL.crypto.X509:
        filename = ",".join(domains)
        crt_path = self.PATH_CERTS.joinpath(f"{filename}.crt")
        with crt_path.open("rb") as fb:
            return OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, fb.read()
            )

    async def renewTask(self, *domains: str) -> None:
        logger.info(f"renewTask {domains}")
        while True:
            crt = await self.getCrt(*domains)
            dt = datetime.datetime.strptime(
                crt.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ"
            )
            if (dt - datetime.timedelta(days=7)) < datetime.datetime.now():
                logger.info(f"Will renew cert for {domains}")
                await self.orderCert(*domains)
            await asyncio.sleep(3600)
