from typing import Any, Tuple, Optional

import os
import asyncio
import ssl
import socket
import multiprocessing
import logging

logger = logging.getLogger(__name__)


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while not reader.at_eof():
            writer.write(await reader.read(2048))
    finally:
        writer.close()


async def open_accepted_socket(
    sock: socket.socket, ssl: Optional[ssl.SSLContext] = None
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)

    transport, _ = await loop.connect_accepted_socket(  # type: ignore
        lambda: protocol, sock=sock, ssl=ssl
    )

    writer = asyncio.StreamWriter(transport, protocol, reader, loop)

    return reader, writer


class ProxyServer:
    def __init__(
        self, local_port: int, remote_host: str, remote_port: int, *domains: str
    ):
        logger.info(
            "Initializing proxy server " f"{local_port}:{remote_host}:{remote_port}"
        )
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.domains = domains
        self.filename = ",".join(domains)
        self.server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    @staticmethod
    async def _subprocess_handler_async(
        accepted: socket.socket,
        peername: Any,
        remote_host: str,
        remote_port: int,
        filename: str,
    ) -> None:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.options |= ssl.OP_NO_TLSv1
        ssl_ctx.options |= ssl.OP_NO_TLSv1_1
        ssl_ctx.options |= ssl.OP_SINGLE_DH_USE
        ssl_ctx.options |= ssl.OP_SINGLE_ECDH_USE

        logger.debug("Loading cert chain")
        ssl_ctx.load_cert_chain(f"./certs/{filename}.crt", f"./certs/{filename}.key")

        if os.getuid() == 0:
            logger.info("We are root, dropping privileges")
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)

        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.VerifyMode.CERT_NONE
        ssl_ctx.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")

        remote_reader, remote_writer = await asyncio.open_connection(
            remote_host, remote_port
        )

        reader, writer = await open_accepted_socket(accepted, ssl=ssl_ctx)

        pipe1 = asyncio.create_task(pipe(remote_reader, writer))
        pipe2 = asyncio.create_task(pipe(reader, remote_writer))

        try:
            await asyncio.wait([pipe1, pipe2])
        finally:
            accepted.close()

        logger.info("subprocess exiting")

    @staticmethod
    def _subprocess_handler(
        accepted: socket.socket,
        peername: Any,
        remote_host: str,
        remote_port: int,
        filename: str,
    ) -> None:
        logger.info(
            f"Forked handler from {peername}, "
            f"will connect to {remote_host}:{remote_port}"
        )
        asyncio.run(
            ProxyServer._subprocess_handler_async(
                accepted, peername, remote_host, remote_port, filename
            )
        )

    async def __run_server(self) -> None:
        logger.info("Running proxy server")
        loop = asyncio.get_event_loop()
        while True:
            socket, peername = await loop.sock_accept(self.server)
            logger.info(f"Accepted socket from {peername}, forking")
            subprocess = multiprocessing.Process(
                target=ProxyServer._subprocess_handler,
                args=(
                    socket,
                    peername,
                    self.remote_host,
                    self.remote_port,
                    self.filename,
                ),
            )
            subprocess.start()

    def run(self) -> asyncio.Task:
        loop = asyncio.get_event_loop()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("::", self.local_port))
        self.server.listen(100)
        self.server.setblocking(False)
        return loop.create_task(self.__run_server())
