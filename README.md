# ACMEasync

AsyncIO ACME client for Python 3.

## Why?
Moar async moar better. Seriously though, I wanted to utilize Python's asyncio to create an automatically certifying proxy server that "just works".

## How?
You can use the library as is, see `acmeasync/__main__.py` and `acmeasync/certbot2.py` as guides for spinning your own implementations, or use the built in tls reverse proxy (currently raw TCP only).

To run the proxy:
```sh
export DOMAINS="example.com,example.net"
export PORT=80 # or whatever port you wish to run the ACME challenge http server on, you need root to serve on 80, or you can forward 8080 if you're running in a docker container for example.
export EMAIL="youremail@example.com"
export PROXIES="8081:towel.blinkenlights.nl:23,8082:towel.blinkenlights.nl:23" # format: localport:remotehost:remoteport,...
export DIRECTORY_URL="https://acme-v02.api.letsencrypt.org/directory"
acmeleproxy
```

It's recommended you run as root so that proxy processes can drop privileges and lose access to your private keys, but this is optional.

API documentation incoming soon...

## But why Python?
Yeah, I know, the GIL, the proxy server uses multiprocessing to spawn a subprocess per connection, which should give much better performance. This kinda thing exists the nodejs world already, why not python too?


## Requirements
Pulled in by setup.py:
- `acme`
- `aiohttp`
- `aiohttp-requests`

Required from your OS:
- `python3-openssl`
