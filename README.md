BoxBot is a Slack bot & a crowler for Livebox 5

To deploy, just use docker-compose
```
version: '2.0'
services:
  boxbot:
    build: .
    volumes:
    - '/your/data/path:/data'
    environment:
      TZ: Europe/Paris
      BOX_USER: USERNAME
      BOX_PASS: PASSWORD
      BOX_IP: IP
      SLACK_TOKEN: TOKEN
      SLACK_CHANNEL: CHANNEL
    restart: always
    entrypoint: 'python /data/boxbot.py'
    tty: true
    stdin_open: true
```

with a Dockerfile in the same place
```
FROM python:3.8.5-alpine

MAINTAINER YanYan

COPY your/local/path/ /data

RUN apk add gcc musl-dev && pip3 install -r /data/requirements.txt
```

To launch properly, you need to had your datas in a folder near your Dockerfile (or a symlink)
