FROM python:3.8.5-alpine

MAINTAINER hexanyn, hexanyn@gmail.com

RUN apk add --no-cache gcc musl-dev postgresql-libs postgresql-dev openssh

RUN pip3 install --no-cache\
	requests\
	slackclient\
	pygments\
	isc_dhcp_leases\
	timeago\
	psycopg2

ENTRYPOINT sh /data/start.sh
