from typing import Any, cast, Dict, TYPE_CHECKING

import asyncio
import datetime

if TYPE_CHECKING:
    from acmeasync.acmele import ACMELE


class Updatable:
    """
    An object that is updatable via post-as-get.
    """

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
    """
    An object that is repr()able.
    """

    data: Dict[str, Any]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} {self.data}"


class Statusable(Updatable):
    """
    An object that has a status field that can be awaited upon changing.
    """

    data: Dict[str, Any]

    @property
    def status(self) -> str:
        return cast(str, self.data["status"])

    async def await_status(self, status: str, timeout: int = 90) -> None:
        """
            Await self.data['status'] being equal to `status`
        """
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
        """
            Await self.data['status'] not being equal to `status`
        """
        end = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
        while self.status == status and datetime.datetime.now() < end:
            await self.update()
            await asyncio.sleep(1)

        if self.status == status:
            raise Exception(
                f"{self} failed to await not status {status}. "
                f"Actual status {self.status}"
            )
