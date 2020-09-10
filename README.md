BoxBot is a Slack bot & a crowler for Livebox 5 & TP-LINK WR841N

To deploy, just use docker-compose
```
version: '2.0'
services:
  bot:
    build: bot/
    volumes:
    - '/your/data/path:/data'
    - '/your/dhcp/path:/dhcp'
    environment:
      TZ: Europe/Paris
      BOX_USER:
      BOX_PASS:
      BOX_IP:
      ROUTER_USER:
      ROUTER_PASS:
      ROUTER_IP:
      RPI_USER:
      RPI_PASS:
      RPI_IP:
      PG_PASS: password
      SLACK_TOKEN:
      SLACK_CHANNEL:
    restart: always
    entrypoint: 'python /data/boxbot.py'
    tty: true
    stdin_open: true
  db:
    build: db/
    environment:
      POSTGRES_PASSWORD: password
      TZ: Europe/Paris
    volumes:
    - './db/data:/var/lib/postgresql/data'
```

with Dockerfiles in subfolder `bot`
```
FROM python:3.8.5-alpine

MAINTAINER YanYan

COPY data/ /data

RUN apk add gcc musl-dev postgresql-libs postgresql-dev && pip3 install -r /data/requirements.txt
```

And another one in subfolder `db`
```
FROM postgres:12.1
MAINTAINER YanYan

COPY srcs/create_db.sql /docker-entrypoint-initdb.d/
```

With this script in `db/srcs/create_db.sql`
```
CREATE DATABASE box;
CREATE TABLE mac_filter (addr macaddr unique, name varchar(50) unique, active boolean);
```

To launch properly, you need to had your datas in a folder near your bot Dockerfile (or a symlink)
