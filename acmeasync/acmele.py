from typing import List, Dict, Any, Optional, Iterable, cast

import asyncio
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

import OpenSSL
import aiohttp
from aiohttp_requests import requests
import josepy as jose
import json

ACC_KEY_BITS = 2048


class Header(jose.Header):  # type: ignore
    nonce = jose.Field("nonce", omitempty=True)
    kid = jose.Field("kid", omitempty=True)
    url = jose.Field("url", omitempty=True)


class Signature(jose.Signature):  # type: ignore
    __slots__ = jose.Signature._orig_slots  # pylint: disable=no-member
    header_cls = Header
    header = jose.Field(
        "header", omitempty=True, default=header_cls(), decoder=header_cls.from_json
    )


class JWS(jose.JWS):  # type: ignore
    signature_cls = Signature
    __slots__ = jose.JWS._orig_slots

    @classmethod
    # pylint: disable=arguments-differ
    def sign(cls, payload, key, alg, nonce, url=None, kid=None):
        # Per ACME spec, jwk and kid are mutually exclusive, so only include a
        # jwk field if kid is not provided.
        include_jwk = kid is None
        return super(JWS, cls).sign(
            payload,
            key=key,
            alg=alg,
            protect=frozenset(["nonce", "url", "kid", "jwk", "alg"]),
            nonce=nonce,
            url=url,
            kid=kid,
            include_jwk=include_jwk,
        )


class Updatable:
    _acme: "ACMELE"
    _location: str
    data: Dict[str, Any]

    def __init__(self, acme: "ACMELE", location: str, data: Dict[str, Any]):
        self._acme = acme
        self._location = location
        self.data = data

    async def update(self) -> "Updatable":
        res = await self._acme._postJWS(self._location)
        data = await res.json()
        self.data = data
        return self


class Representable:
    data: Dict[str, Any]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} {self.data}"


class Statusable(Updatable):
    data: Dict[str, Any]

    @property
    def status(self) -> str:
        return cast(str, self.data["status"])

    async def await_status(self, status: str, timeout: int = 90) -> None:
        end = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
        while self.status != status and datetime.datetime.now() < end:
            await self.update()
            await asyncio.sleep(1)

        if self.status != status:
            raise Exception(
                f"{self} failed to await status {status}. "
                f"Actual status {self.status}"
            )

    async def await_not_status(self, status: str, timeout: int = 90) -> None:
        end = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
        while self.status == status and datetime.datetime.now() < end:
            await self.update()
            await asyncio.sleep(1)

        if self.status == status:
            raise Exception(
                f"{self} failed to await not status {status}. "
                f"Actual status {self.status}"
            )


class Challenge(Statusable, Representable):
    def __init__(self, acme: "ACMELE", location: str, data: Dict[str, Any]):
        super().__init__(acme, location, data)

    async def begin(self) -> "Challenge":
        res = await self._acme._postJWS(self._location, {})
        data = await res.json()
        self.data = data
        return self


class Authorization(Statusable, Representable):
    def __init__(self, acme: "ACMELE", location: str, data: Dict[str, Any]):
        super().__init__(acme, location, data)

    async def challenges(self, challType: Optional[str] = None) -> List[Challenge]:
        return [
            Challenge(self._acme, chall["url"], chall)
            for chall in self.data["challenges"]
            if challType is None or chall["type"] == challType
        ]


class Order(Statusable, Representable):
    def __init__(self, acme: "ACMELE", location: str, data: Dict[str, Any]):
        super().__init__(acme, location, data)

    async def authorizations(self) -> List[Authorization]:
        return [
            Authorization(
                self._acme, auth, await (await self._acme._postJWS(auth)).json()
            )
            for auth in self.data["authorizations"]
        ]

    async def finalize(self, csr_bytes: bytes) -> "Order":
        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, csr_bytes
        )
        res = await self._acme._postJWS(
            self.data["finalize"], {"csr": jose.encode_csr(jose.ComparableX509(csr))}
        )
        data = await res.json()
        self.data = data

        return self

    async def get_cert(self) -> str:
        res = await self._acme._postJWS(self.data["certificate"])
        return await res.text()


class ACMELE:
    __directory_url: str
    __nonce: Optional[str]
    __account_key: Optional[jose.JWK]
    __kid: Optional[str]

    def __init__(self, directory_uri: str):
        self.__directory_uri = directory_uri
        self.__nonce = None
        self.__account_key = None
        self.__kid = None

    @property
    def account_key_thumbprint(self) -> Optional[str]:
        if self.__account_key is None:
            return None
        return cast(
            str, jose.b64encode(self.__account_key.thumbprint()).decode("ascii")
        )

    async def begin(self) -> None:
        res = await requests.get(self.__directory_uri)
        self.__directory = await res.json()
        res = await requests.head(self.__directory["newNonce"])
        self.__nonce = res.headers["Replay-Nonce"]

    async def __post(self, *args: Any, **kwargs: Any) -> aiohttp.ClientResponse:
        res = await requests.post(*args, **kwargs)
        nonce = res.headers.get("Replay-Nonce")
        if nonce is not None:
            self.__nonce = nonce

        return cast(aiohttp.ClientResponse, res)

    async def _postJWS(
        self, url: str, body: Optional[Dict[str, Any]] = None
    ) -> aiohttp.ClientResponse:
        data = JWS.sign(
            json.dumps(body).encode("ascii") if body is not None else b"",
            key=self.__account_key,
            alg=jose.jwa.RS256,
            nonce=self.__nonce,
            kid=self.__kid,
            url=url,
        ).json_dumps()

        return await self.__post(
            url, data=data, headers={"Content-Type": "application/jose+json"}
        )

    async def loadAccount(self, filename: str) -> bool:
        pathKey = Path(filename)
        if not pathKey.exists():
            return False
        with pathKey.open("r") as file:
            self.__account_key = jose.JWKRSA.json_loads(file.read())

        res = await self._postJWS(
            self.__directory["newAccount"],
            {"key": self.__account_key.to_json(), "onlyReturnExisting": True},
        )

        if "Location" not in res.headers:
            return False

        self.__kid = res.headers["Location"]

        return True

    async def createAccount(self, email: str, termsOfServiceAgreed: bool) -> bool:
        if not self.__account_key:
            self.__account_key = jose.JWKRSA(
                key=rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=ACC_KEY_BITS,
                    backend=default_backend(),
                )
            )

        res = await self._postJWS(
            self.__directory["newAccount"],
            {
                "contact": [f"mailto:{email}"],
                "termsOfServiceAgreed": termsOfServiceAgreed,
            },
        )

        data = await res.json()
        self.__kid = res.headers["Location"]

        return bool(data["status"] == "valid")

    async def saveAccount(self, filename: str) -> bool:
        if not self.__account_key:
            return False
        with Path(filename).open("w") as file:
            file.write(self.__account_key.json_dumps())
        return True

    async def createOrder(self, domains: Iterable[str]) -> Order:
        payload = json.dumps(
            {"identifiers": [{"type": "dns", "value": domain} for domain in domains]}
        ).encode("ascii")

        body = JWS.sign(
            payload,
            key=self.__account_key,
            alg=jose.jwa.RS256,
            nonce=self.__nonce,
            kid=self.__kid,
            url=self.__directory["newOrder"],
        ).json_dumps()

        res = await self.__post(
            self.__directory["newOrder"],
            data=body,
            headers={"Content-Type": "application/jose+json"},
        )

        data = await res.json()
        return Order(self, res.headers["Location"], data)
