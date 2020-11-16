FROM python:3.8.5-alpine

MAINTAINER hexanyn, hexanyn@gmail.com

RUN apk add gcc musl-dev postgresql-libs postgresql-dev

RUN pip3 install --no-cache/
	requests\
	slackclient\
	pygments\
	isc_dhcp_leases\
	timeago\
	psycopg2

ENTRYPOINT sh /data/start.sh