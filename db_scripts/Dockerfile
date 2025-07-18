FROM python:3.13-alpine AS build

RUN apk update \
    && apk add build-base libpq libpq-dev

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.13-alpine AS final

# libpq-dev not needed in final build.
RUN apk update \
    && apk upgrade \
    && apk add --no-cache libpq

COPY --from=build /usr/local/lib/python3.13/site-packages/ /usr/local/lib/python3.13/site-packages/

WORKDIR /app

COPY . ./

ENTRYPOINT [ "python", "rpki-history-db.py"]