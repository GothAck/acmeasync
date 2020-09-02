# API

There are two levels of abstraction on top of the ACME HTTP API:
* :class:`.ACMELE` sits directly on top of the HTTP API, providing a near-metal interface
* :class:`.CertBot2` tries to emulate some of the functionality from certbot, giving the user a few simple methods to call instead of having to deal with the back-and-forth involved in ordering a cert. :class:`.CertBot2` also provides :func:`~acmeasync.certbot2.CertBot2.http01ChallengeHandler` which needs to be added as a route handler for an aiohttp :class:`~aiohttp.web.Application`.
