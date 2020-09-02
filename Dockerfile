FROM python:3.8-alpine AS build

RUN pip install pipenv

WORKDIR /app

RUN apk add build-base gcc musl-dev libffi-dev openssl-dev python3-dev

COPY . .
ENV PIPENV_VENV_IN_PROJECT=1
RUN pipenv sync

FROM python:3.8-alpine

RUN pip install pipenv

COPY --from=build /app/* ./
COPY --from=build /app/.venv ./
ENV PIPENV_VENV_IN_PROJECT=1
ENTRYPOINT ["pipenv", "run", "python", "-m", "acmeasync"]
