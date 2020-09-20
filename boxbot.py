#!/usr/bin/python3
# -*- coding: latin-1 -*-

import requests, json, slack, os, subprocess, isc_dhcp_leases, timeago, datetime, re, psycopg2, math
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter
from utils import *

class boxbot:
	def __init__(self):
		self.bot_token = os.environ.get('SLACK_TOKEN')
		self.bot = slack.RTMClient(token=self.bot_token)
		self.client = slack.WebClient(self.bot_token)
		self.private_channel = [os.environ.get('SLACK_CHANNEL'), "D012FT2M6MA"]
		self.ensure_slack()
		self.session = requests.session()
		self.uribox = "http://{}/ws".format(os.environ.get('BOX_IP'))
		self.uriwrt = {
			'rpi': "http://{}/cgi-bin/luci/rpc".format(os.environ.get('RPI_IP')),
			'router': "http://{}/cgi-bin/luci/rpc".format(os.environ.get('ROUTER_IP'))
		}
		self.headers = {
			'auth': {
				'Content-Type': 'application/x-sah-ws-4-call+json',
				'Authorization': 'X-Sah-Login'
			},
			'data': {
				'Content-Type': 'application/x-sah-ws-4-call+json',
				'X-Context': ''
			}
		}
		self.auth_payload = {
			'service': 'sah.Device.Information',
			'method': 'createContext',
			'parameters': {
				'applicationName': 'so_sdkut',
				'username': os.environ.get('BOX_USER'),
				'password': os.environ.get('BOX_PASS')
			}
		}
		self.pg = psycopg2.connect(
			host="db",
			database="box",
			user="postgres",
			password=os.environ.get("PG_PASS")
		)
		self.cur = self.pg.cursor()
		self.wrt_token = {"rpi": False, "router": False}
		slack.RTMClient.run_on(event='message')(self.run)
		self.bot.start()

	def ensure_slack(self):
		self.bot_info = self.client.api_call("auth.test")
		if self.bot_info.get("ok") is True:
			print("✅ Connection succed\n",
				f"{yellow('team')} : {blue(self.bot_info['team'])}\n",
				f"{yellow('user')} : {blue(self.bot_info['user'])}\n")
		else:
			print("❌ Connection failed\nRetry...")
			self.__init__()
	
	def parse_line(self, line):
		args = self.line[1:].strip().split(' ')
		self.cmd = args[0].lower()
		self.args = args[1:]
	
	def is_for_me(self):
		if self.data["text"] and self.data["blocks"][0]["elements"][0]["elements"][0]["text"]: self.line = " ".join(self.data["blocks"][0]["elements"][0]["elements"][0]["text"].split())
		if (not (self.data.get("bot_id")) and
			self.data["text"] and
			self.line[0] == "!" and
			self.data["channel"] in self.private_channel): #and
			#event.get("user") in self.allowed_users):
			return True
		else:
			return False
	
	def output(self, message, attachments=None):
#		if as_json:
#			print(highlight(json.dumps(message, indent=4), JsonLexer(), TerminalFormatter()))
#		else:
#			print(message)
		self.client.chat_postMessage(
			channel=self.data["channel"],
			text=message,
			as_user=True,
			attachments=attachments
		)
	
	def reqbox(self, payload={}, check=True):
		if not check: self.headers['data']['X-Context'] = self.session.post(self.uribox, headers=self.headers['auth'], json=self.auth_payload).json()['data']['contextID']
		r = self.session.post(self.uribox, headers=self.headers['data'], json=payload).json()
		if check:
			if r['status'] == None:
				r = self.session.post(self.uribox, headers=self.headers['auth'], json=self.auth_payload).json()
				if r['status'] != 0:
					return False
				else:
					self.headers['data']['X-Context'] = r['data']['contextID']
					return self.reqbox(payload)
			else:
				return r['status']
		else:
			return False
	
	def reqwrt(self, uri='router', payload={}):
		r = requests.get(f"{self.uriwrt[uri]}/uci?auth={self.wrt_token[uri]}", json=payload)
		if r.status_code == 200:
			return r.json()['result']
		else:
			if self.wrt_token[uri] == None:
				self.wrt_token[uri] = False
				return None
			else:
				self.wrt_token[uri] = None
				self.connect_wrt(uri)
				return self.reqwrt(uri, payload)

	def connect_wrt(self, uri):
		payload = {
			'id': 1,
			'method': 'login',
			'params': [
				os.environ.get(f"{uri.upper()}_USER"),
				os.environ.get(f"{uri.upper()}_PASS")
			]
		}
		r = requests.get("{}/auth".format(self.uriwrt[uri]), json=payload)
		if r.status_code == 200:
			self.wrt_token[uri] = r.json()['result']
	
	def apply_wrt(self, uri='router'):
		payload = {'method': 'apply'}
		self.reqwrt(uri, payload)

	def unable_fetch(self, out="Unknown"):
		self.output(f"Unable to retrieve datas... ({out})")

	# PUBLIC METHOD
	
	def devices(self):
		payload = {'service': 'Devices', 'method': 'get', 'parameters': {'expression': {'ETHERNET': 'not interface and not self and eth and .Active==true', 'WIFI': 'not interface and not self and wifi and .Active==true'}}}
		r = self.reqbox(payload)
		if not r:
			self.unable_fetch()
		else:
			attachments = []
			leases = isc_dhcp_leases.IscDhcpLeases('/dhcp/dhcpd.leases').get_current()
			devices = {}
			for interface in r:
				for item in r[interface]:
					if item['PhysAddress'].lower() in leases or item['IPAddress']:
						lease = leases[item['PhysAddress'].lower()] if item['PhysAddress'].lower() in leases else None
						if item['InterfaceName'] not in devices: devices[item['InterfaceName']] = []
						firstseen = timeago.format(datetime.datetime.strptime(item['FirstSeen'], "%Y-%m-%dT%H:%M:%SZ"), datetime.datetime.now())
						lastseen = timeago.format(datetime.datetime.strptime(item['LastConnection'], "%Y-%m-%dT%H:%M:%SZ"), datetime.datetime.now())
						devices[item['InterfaceName']].append({
							'blocks': [
								{
									'type': 'section',
									'text': {
										'type': 'mrkdwn',
										'text': f"*{item['Name']}*"
									},
									'fields': [
										{
											'type': 'mrkdwn',
											'text': lease.ip if lease else item['IPAddress']
										},
										{
											'type': 'mrkdwn',
											'text': item['PhysAddress']
										},
										{
											'type': 'mrkdwn',
											'text': item['InterfaceName']
										}
									]
								},
								{
									'type': 'context',
									'elements': [
										{
											'type': 'mrkdwn',
											'text': 'First: {}'.format(firstseen)
										},
										{
											'type': 'mrkdwn',
											'text': 'Last: {}'.format(lastseen)
										}
									]
								}
							]
						})
			for interface in sorted(devices):
				for item in devices[interface]:
					attachments.append(item)
			self.output('Connected devices', attachments)
	
	def dhcp(self):
		attachments = []
		leases = isc_dhcp_leases.IscDhcpLeases('/dhcp/dhcpd.leases').get_current()
		for lease in leases:
			lease = leases[lease]
			attachments.append({
				'blocks': [
					{
						'type': 'section',
						'text': {
							'type': 'mrkdwn',
							'text': f"*{lease.hostname}*"
						},
						'fields': [
							{
								'type': 'mrkdwn',
								'text': lease.ip
							},
							{
								'type': 'mrkdwn',
								'text': lease.ethernet
							}
						]
					}
				]
			})
		self.output("DHCP Leases", attachments)

	def ports(self):
		payload = {'service': 'Firewall', 'method': 'getPortForwarding', 'parameters': {'origin': 'webui'}}
		r = self.reqbox(payload)
		if not r:
			self.unable_fetch()
		else:
			attachments = []
			for item in r:
				item = r[item]
				if not item['SourcePrefix']: item['SourcePrefix'] = '0.0.0.0'
				attachments.append({
					'color': '#00ff00' if item['Enable'] else '#ff0000',
					'blocks': [
						{
							'type': 'section',
							'text': {
								'type': 'mrkdwn',
								'text': f"*{item['Description']}*"
							},
							'fields': [
								{
									'type': 'mrkdwn',
									'text': f"*Source*\n{item['SourcePrefix']}:{item['ExternalPort']}"
								},
								{
									'type': 'mrkdwn',
									'text': f"*Destination*\n{item['DestinationIPAddress']}:{item['InternalPort']}"
								}
							]
						}
					]
				})
			self.output('Ports Forward', attachments)

	def mac(self):
		self.cur.execute("SELECT * FROM mac_filter ORDER BY name ASC;");
		devices = {}
		devicesall = {}
		attachments = []
		index = 0
		interfaces = {}
		for inter in ["Box eth4", "Box wl0", "Router", "OpenWRT"]:
			interfaces[inter] = {"state": True, "to_del": [], "to_add": []}
		for entry in self.cur.fetchall():
			devicesall[entry[0]] = entry[1]
			if not entry[2]: continue
			index += 1
			if entry[0] not in devices:
				devices[entry[0]] = []
			devices[entry[0]] = entry[1]
			attachments.append({
				'color': '#00ff00' if entry[2] else '#ff0000',
				'blocks': [
					{
						'type': 'section',
						'fields': [
							{
								'type': 'mrkdwn',
								'text': f"{entry[1]}"
							},
							{
								'type': 'mrkdwn',
								'text': f"{entry[0]}"
							}
						]
					}
				]
			})
		self.output('Permitted devices', attachments)

		payload = {"service":"NeMo.Intf.lan","method":"getMIBs","parameters":{"mibs":"wlanvap"}}
		r = self.reqbox(payload)
		if not r:
			self.unable_fetch("Box")
			interfaces['Box eth4']['state'] = False
			interfaces['Box wl0']['state'] = False
		else:
			for interface in ["eth4", "wl0"]:
				attachments = []
				rtmp = r['wlanvap'][interface]['MACFiltering']['Entry']
				devicestmp = devices.copy()
				for item in rtmp:
					index = item
					item = rtmp[item]
					item['MACAddress'] = item['MACAddress'].lower()
					if item['MACAddress'] not in devicestmp:
						interfaces[f"Box {interface}"]['state'] = False
						if item['MACAddress'] in devicesall: name = devicesall[item['MACAddress']]
						else: name = item['MACAddress']
						interfaces[f"Box {interface}"]['to_del'].append(name)
					devicestmp.pop(item['MACAddress'], None)
				if len(devicestmp) > 0:
					interfaces[f"Box {interface}"]['state'] = False
					interfaces[f"Box {interface}"]['to_add'].extend(devicestmp.values())

		for interface in {'router': 'Router', 'rpi': 'OpenWRT'}.items():
			payload = {'method': 'get', 'params': ['wireless', 'default_radio0', 'maclist']}
			r = self.reqwrt(interface[0], payload)
			if not r:
				self.unable_fetch(interface[1])
				interfaces[interface[1]]['state'] = False
			else:
				devicestmp = devices.copy()
				for addr in r:
					addr = addr.lower()
					if addr not in devicestmp:
						interfaces[interface[1]]['state'] = False
						if addr in devicesall: name = devicesall[addr]
						else: name = addr
						interfaces[interface[1]]['to_del'].append(name)
					devicestmp.pop(addr, None)
				if len(devicestmp) > 0:
					interfaces[interface[1]]['state'] = False
					interfaces[interface[1]]['to_add'].extend(devicestmp.values())

		out = []
		for inter in interfaces:
			outtmp = f"{':heavy_check_mark:' if interfaces[inter]['state'] else ':x:'} {inter}"
			if interfaces[inter]['to_del']: outtmp += f"\n	| to_del: {', '.join(sorted(interfaces[inter]['to_del']))}"
			if interfaces[inter]['to_add']: outtmp += f"\n	| to_add: {', '.join(sorted(interfaces[inter]['to_add']))}"
			out.append(outtmp)
		self.output("\n".join(out))
	
	def mac_db(self):
		if len(self.args) == 0:
			self.cur.execute("SELECT * FROM mac_filter ORDER BY active DESC, name;");
			attachments = []
			index = 0
			for entry in self.cur.fetchall():
				index += 1
				attachments.append({
					'color': '#00ff00' if entry[2] else '#ff0000',
					'blocks': [
						{
							'type': 'section',
							'fields': [
								{
									'type': 'mrkdwn',
									'text': f"{entry[1]}"
								},
								{
									'type': 'mrkdwn',
									'text': f"{entry[0]}"
								}
							]
						}
					]
				})
			self.output('Saved mac address', attachments)
		elif self.args[0] in ["create", "add", "new"]:
			if len(self.args) < 3:
				self.output("Missing args")
			else:
				try:
					postgres_insert_query = """ INSERT INTO mac_filter (name, addr, active) VALUES (%s,%s,True)"""
					record_to_insert = (self.args[1], self.args[2].replace('-', ':'))
					self.cur.execute(postgres_insert_query, record_to_insert)

					self.pg.commit()
					self.args = []
					self.mac_db()

				except (Exception, psycopg2.Error) as error:
					self.output("An error occured when creating")
					print(error)
					if(self.pg):
						self.pg.rollback()
		elif self.args[0] in ["remove", "delete", "rm", "del"]:
			if len(self.args) < 2:
				self.output("Missing args")
			else:
				try:
					postgres_insert_query = """ DELETE FROM mac_filter WHERE name=%s """
					records = []
					for arg in self.args[1:]:
						records.append([arg])
					self.cur.executemany(postgres_insert_query, records)

					self.pg.commit()
					self.args = []
					self.mac_db()

				except (Exception, psycopg2.Error) as error:
					self.output("An error occured when deleting")
					print(error)
					if(self.pg):
						self.pg.rollback()
		elif self.args[0] in ["enable", "active", "on"]:
			if len(self.args) < 2:
				self.output("Missing args")
			else:
				try:
					postgres_insert_query = """ UPDATE mac_filter SET active=True WHERE active=False AND name=%s """
					records = []
					for arg in self.args[1:]:
						records.append([arg])
					self.cur.executemany(postgres_insert_query, records)

					self.pg.commit()
					self.args = []
					self.mac_db()

				except (Exception, psycopg2.Error) as error:
					self.output("An error occured when updating")
					print(error)
					if(self.pg):
						self.pg.rollback()
		elif self.args[0] in ["disable", "off"]:
			if len(self.args) < 2:
				self.output("Missing args")
			else:
				try:
					postgres_insert_query = """ UPDATE mac_filter SET active=False WHERE active=True AND name=%s """
					records = []
					for arg in self.args[1:]:
						records.append([arg])
					self.cur.executemany(postgres_insert_query, records)

					self.pg.commit()
					self.args = []
					self.mac_db()

				except (Exception, psycopg2.Error) as error:
					self.output("An error occured when updating")
					print(error)
					if(self.pg):
						self.pg.rollback()
			
			
	def mac_sync(self):
		self.output("Updating hotspots...")
		self.cur.execute("SELECT * FROM mac_filter WHERE active=True;");
		index = 0
		devices = {'box': {}, 'router': {}}
		for entry in self.cur.fetchall():
			index += 1
			devices['box'][index] = {'MACAddress': entry[0].upper()}
			devices['router'][entry[0]] = entry[1]
		for interface in ['eth4', 'wl0']:
			payload = {"service":f"NeMo.Intf.{interface}","method":"setWLANConfig","parameters":{"mibs":{"wlanvap":{interface:{"MACFiltering":{"Entry":devices["box"]}}}}}}
			self.reqbox(payload, check=False)
			self.output(f"Box ({interface}) updated")
		payload = {'method': 'set', 'params': ['wireless', 'default_radio0', 'maclist', list(devices['router'].keys())]}
		for interface in {'router': 'Router', 'rpi': 'OpenWRT'}.items():
			self.reqwrt(interface[0], payload)
			self.apply_wrt(interface[0])
			self.output(f"{interface[1]} updated")
		self.mac()

	
	def help(self):
		self.output("""
`  !who   ` - Show devices connected
`  !dhcp  ` - Show active dhcp leases
` !ports  ` - Show port forward
`  !mac   ` - Show whitelisted mac address
` !mac_db ` - Manage database
		Usage: `!mac_db [<create|remove|active|disable> <NAME> [MacAddr]]`
`!mac_sync` - Synchronise hotspot with active devices in database
`  !help  ` - Display this help
		""")
	
	def dispatch(self):
		if   self.cmd == "who":			self.devices()
		elif self.cmd == "dhcp":		self.dhcp()
		elif self.cmd == "ports":		self.ports()
		elif self.cmd == "mac":			self.mac()
		elif self.cmd == "mac_db":		self.mac_db()
		elif self.cmd == "mac_sync":	self.mac_sync()
		elif self.cmd == "help":		self.help()
		elif self.cmd == "info":		self.help()
	
	def run(self, **event):
		self.event = event
		self.data = self.event["data"]
		if self.is_for_me() == True:
			try:
				print(self.line)
				self.parse_line(self.line)
				self.dispatch()
			except Exception as e:
				print(e)

if __name__ == "__main__":
	box = boxbot()
