#!/usr/bin/python3
# -*- coding: latin-1 -*-

import requests, json, slack, os, subprocess, isc_dhcp_leases, timeago, datetime, re, psycopg2, math, time, logging
from threading import Thread
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter
from utils import *

class boxbot:
	def __init__(self):
		self.bot_token = os.environ.get('SLACK_TOKEN')
		self.bot = slack.RTMClient(token=self.bot_token)
		self.client = slack.WebClient(self.bot_token)
		self.private_channel = [os.environ.get('SLACK_CHANNEL'), "D012FT2M6MA", "D012ZHFNKLY"]
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
			database=os.environ.get("POSTGRES_USER"),
			user=os.environ.get("POSTGRES_USER"),
			password=os.environ.get("POSTGRES_PASSWORD")
		)
		self.cur = self.pg.cursor()
		self.cur.execute("CREATE TABLE IF NOT EXISTS mac_filter (addr macaddr unique, name varchar(50) unique, active boolean);")
		self.cur.execute("CREATE TABLE IF NOT EXISTS authorized_keys (key text unique, name varchar(50) unique, fingerprint text unique, active boolean);")
		self.pg.commit()
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
		args = line[1:].strip().split(' ')
		self.cmd = args[0].lower()
		self.args = args[1:]
	
	def is_for_me(self):
		self.line = []
		for elem in self.data['blocks'][0]['elements'][0]['elements']:
			self.line.append(elem['text'].strip())
		self.line = ' '.join(self.line)
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
	
	def reqbox(self, payload={}, check=True, timeout=10):
		if not check: self.headers['data']['X-Context'] = self.session.post(self.uribox, headers=self.headers['auth'], json=self.auth_payload).json()['data']['contextID']
		r = self.session.post(self.uribox, headers=self.headers['data'], json=payload, timeout=timeout).json()
		if check:
			if r['status'] == None:
				r = self.session.post(self.uribox, headers=self.headers['auth'], json=self.auth_payload, timeout=timeout).json()
				if r['status'] != 0:
					return False
				else:
					self.headers['data']['X-Context'] = r['data']['contextID']
					return self.reqbox(payload)
			else:
				return r['status']
		else:
			return False
	
	def reqwrt(self, uri='router', payload={}, timeout=10):
		r = requests.get(f"{self.uriwrt[uri]}/uci?auth={self.wrt_token[uri]}", json=payload, timeout=timeout)
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

	def connect_wrt(self, uri, timeout=10):
		payload = {
			'id': 1,
			'method': 'login',
			'params': [
				os.environ.get(f"{uri.upper()}_USER"),
				os.environ.get(f"{uri.upper()}_PASS")
			]
		}
		r = requests.get("{}/auth".format(self.uriwrt[uri]), json=payload, timeout=timeout)
		if r.status_code == 200:
			self.wrt_token[uri] = r.json()['result']
	
	def apply_wrt(self, uri='router'):
		payload = {'method': 'apply'}
		self.reqwrt(uri, payload)

	def unable_fetch(self, out="Unknown"):
		self.output(f"Unable to retrieve datas... ({out})")
	
	def get_dhcpd(self):
		with open('/dhcp/dhcpd.conf') as f:
			dhcpd = f.readlines()
		in_brackets = False
		devices = {}
		for line in dhcpd:
			if in_brackets == False and "	host " in line:
				name = "."
				host = "."
				addr = "."
				name = line.split(' ')[1]
				in_brackets = True
			elif in_brackets == True and "ethernet" in line:
				host = line.split(' ')[2][:-2].upper()
			elif in_brackets == True and "fixed-address" in line:
				addr = line.split(' ')[1][:-2]
			elif in_brackets == True and "}" in line:
				in_brackets = False
				devices[host] = {'name': name, 'addr': addr}
		return devices
	
	def update_names(self, devices={}):
		payload = {'service': 'Devices', 'method': 'get', 'parameters': {}}
		r = self.reqbox(payload)
		known_devices = {}
		status = {'good': [], 'bad': [], 'unknown': []}
		assoc = {'good': ':heavy_check_mark:', 'bad': ':x:', 'unknown': ':interrobang:'}
		if not r:
			self.output("unable to fetch")
		else:
			for device in r:
				if device['DiscoverySource'] in ['bridge', 'dhcp', 'import']:
					known_devices[device['Key'].upper()] = device
		self.output("Updating {} names...".format(len(devices)))
		for addr in devices:
			name = devices[addr]['name']
			if addr in known_devices:
				r = self.reqbox({'service':"Devices.Device.{}".format(addr),'method':'setName','parameters':{'name':name}})
				state = 'bad' if not r else 'good'
			else:
				state = 'unknown'
			status[state].append(name)
		output = []
		for state in status:
			if len(status[state]) > 0:
				output.append("{} {}".format(assoc[state], ', '.join(status[state])))
		if len(output) > 0:
			self.output('\n'.join(output))


	# PUBLIC METHOD
	
	def devices(self):
		payload = {'service': 'Devices', 'method': 'get', 'parameters': {'expression': {'ALL': 'not interface and not self and (eth or wifi) and .Active==true'}}}
		r = self.reqbox(payload)
		if not r:
			self.unable_fetch()
		else:
			attachments = []
			leases = isc_dhcp_leases.IscDhcpLeases('/dhcp/dhcpd.leases').get_current()
			dhcpd = self.get_dhcpd()
			dhcp = {}
			for lease in leases:
				dhcp[leases[lease].ethernet.lower()] = leases[lease].ip
			for entry in dhcpd:
				dhcp[entry.lower()] = dhcpd[entry]['addr']
			devices = {}
			for item in r['ALL']:
				if item['PhysAddress'].lower() in dhcp or item['IPAddress']:
					ip = dhcp[item['PhysAddress'].lower()] if item['PhysAddress'].lower() in dhcp else item['IPAddress']
					if len(self.args) > 0 and self.args[0] in item:
						sorting_key = item[self.args[0]]
					else:
						sorting_key = int(ip.replace('.', ''))
					if sorting_key not in devices: devices[sorting_key] = []
					firstseen = timeago.format(datetime.datetime.strptime(item['FirstSeen'], "%Y-%m-%dT%H:%M:%SZ"), datetime.datetime.now())
					lastseen = timeago.format(datetime.datetime.strptime(item['LastConnection'], "%Y-%m-%dT%H:%M:%SZ"), datetime.datetime.now())
					devices[sorting_key].append({
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
										'text': ip
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
				else:
					self.output("Unknown device {} ({}) :(".format(item['Name'], item['PhysAddress']))
			count_device = 0
			for index in sorted(devices):
				for item in devices[index]:
					attachments.append(item)
					count_device += 1
			self.output(f"*{count_device}* connected devices (you can also sort by `Name`, `InterfaceName`)", attachments)
	
	def dhcp(self):
		devices = self.get_dhcpd()
		attachments = []
		for host in devices:
			name = devices[host]['name']
			addr = devices[host]['addr']
			attachments.append({
				'blocks': [
					{
						'type': 'section',
						'text': {
							'type': 'mrkdwn',
							'text': f"*{name}*"
						},
						'fields': [
							{
								'type': 'mrkdwn',
								'text': addr
							},
							{
								'type': 'mrkdwn',
								'text': host
							}
						]
					}
				]
			})
		self.output("Static address", attachments)

	def dhcp_sync(self):
		self.update_names(self.get_dhcpd())

	def leases(self):
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
			protocols_name = {'6': 'TCP', '17': 'UDP'}
			for item in r:
				item = r[item]
				if not item['SourcePrefix']: item['SourcePrefix'] = '0.0.0.0'
				protocols = []
				for protocol in item['Protocol'].split(','):
					protocols.append({
						'type': 'mrkdwn',
						'text': protocols_name[protocol] if protocol in protocols_name else "#{}".format(protocol)
					})
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
						},
						{
							'type': 'context',
							'elements': protocols
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
		for inter in ["Box wl0", "Box eth4", "Router 2.4G", "Router 5G", "OpenWRT"]:
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
			interfaces['Box wl0']['state'] = False
			interfaces['Box eth4']['state'] = False
		else:
			for interface in ["wl0", "eth4"]:
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

		for interface in {'Router 2.4G': ['router', 'wifinet0'], 'Router 5G': ['router', 'wifinet1'], 'OpenWRT': ['rpi', 'default_radio0']}.items():
			payload = {'method': 'get', 'params': ['wireless', interface[1][1], 'maclist']}
			r = self.reqwrt(interface[1][0], payload)
			if not r:
				self.unable_fetch(interface[0])
				interfaces[interface[0]]['state'] = False
			else:
				devicestmp = devices.copy()
				for addr in r:
					addr = addr.lower()
					if addr not in devicestmp:
						interfaces[interface[0]]['state'] = False
						if addr in devicesall: name = devicesall[addr]
						else: name = addr
						interfaces[interface[0]]['to_del'].append(name)
					devicestmp.pop(addr, None)
				if len(devicestmp) > 0:
					interfaces[interface[0]]['state'] = False
					interfaces[interface[0]]['to_add'].extend(devicestmp.values())

		out = []
		for inter in interfaces:
			outtmp = f"{':heavy_check_mark:' if interfaces[inter]['state'] else ':x:'} {inter}"
			if interfaces[inter]['to_del']: outtmp += f"\n	| to_del: {', '.join(sorted(interfaces[inter]['to_del']))}"
			if interfaces[inter]['to_add']: outtmp += f"\n	| to_add: {', '.join(sorted(interfaces[inter]['to_add']))}"
			out.append(outtmp)
		self.output("\n".join(out))
			
			
	def mac_sync(self):
		self.output("Updating hotspots...")
		self.cur.execute("SELECT * FROM mac_filter WHERE active=True;");
		index = 0
		devices = {'box': {}, 'router': {}}
		for entry in self.cur.fetchall():
			index += 1
			devices['box'][index] = {'MACAddress': entry[0].upper()}
			devices['router'][entry[0]] = entry[1]
		self.output("Livebox is limited to 15 devices, automatic update is therefore disabled")
#		for interface in ['wl0', 'eth4']:
#			payload = {"service":f"NeMo.Intf.{interface}","method":"setWLANConfig","parameters":{"mibs":{"wlanvap":{interface:{"MACFiltering":{"Entry":devices["box"]}}}}}}
#			self.reqbox(payload, check=False)
##			payload = {"service":f"NeMo.Intf.{interface}","method":"setWLANConfig","parameters":{"mibs":{"wlanvap":{interface:{"MACFiltering":{"Mode":"WhiteList"}}}}}}
##			self.reqbox(payload, check=False)
##			payload = {"service":f"NeMo.Intf.{interface}","method":"setWLANConfig","parameters":{"mibs":{"wlanvap":{interface:{"WPS":{"Enable":false}}}}}}
##			self.reqbox(payload, check=False)
#			self.output(f"Box ({interface}) updated")
		payload = {'method': 'set', 'params': ['wireless', '', 'maclist', list(devices['router'].keys())]}
		for interface in {'Router 2.4G': ['router', 'wifinet0'], 'Router 5G': ['router', 'wifinet1'], 'OpenWRT': ['rpi', 'default_radio0']}.items():
			payload['params'][1] = interface[1][1]
			self.reqwrt(interface[1][0], payload)
			self.output(f"{interface[0]} updated")
		for interface in ['router', 'rpi']:
			self.apply_wrt(interface)
		self.mac()
	
	def mac_db(self):
		if len(self.args) == 0:
			self.cur.execute("SELECT * FROM mac_filter ORDER BY active DESC, name;");
			attachments = []
			for entry in self.cur.fetchall():
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

	def db_sync(self):
		self.cur.execute("SELECT * FROM mac_filter ORDER BY active DESC, name;");
		db_devices = self.cur.fetchall()
		devices = {}
		for entry in db_devices:
			devices[entry[0].upper()] = {'name': entry[1]}
		self.update_names(devices)
	
	def names_sync(self):
		self.db_sync()
		self.dhcp_sync()
	
	def wake(self):
		if len(self.args) < 1:
			self.output('Missing one or more dhcp name')
		else:
			devices = self.get_dhcpd()
			for arg in self.args:
				success = False
				for addr in devices:
					if devices[addr]['name'] == arg:
						self.output("Wake up {} ({})".format(arg, addr))
						r = requests.get("https://endpoints.hexanyn.fr/wakeonlan.php?addr={}".format(addr))
						if r.status_code == 200:
							self.output(r.text)
						else:
							self.output("Wake on lan endpoints return an error")
						success = True
						break
				if not success:
					self.output("Device {} not found :(".format(arg))
	
	def dns_sync(self):
		self.output("Updating zonefile")
		dhcp = self.get_dhcpd()
		subprocess.call('cp /dns/home.hosts.base /dns/home.hosts', shell=True)
		subprocess.call('cp /dns/1.168.192.in-addr.arpa.base /dns/1.168.192.in-addr.arpa', shell=True)
		f_dns = open('/dns/home.hosts', 'a')
		f_reverse = open('/dns/1.168.192.in-addr.arpa', 'a')
		for host in dhcp:
			addr = dhcp[host]['addr']
			if addr != '.':
				f_dns.write("{}	IN	A	{}\n".format(dhcp[host]['name'], dhcp[host]['addr']))
				f_reverse.write("{}	IN	PTR	{}.home.\n".format(dhcp[host]['addr'].split('.')[-1], dhcp[host]['name']))
		f_dns.close()
		f_reverse.close()
		r = requests.get("https://endpoints.hexanyn.fr/dns.php?action=restart")
		if r.status_code == 200:
			self.output(r.text)
		else:
			self.output("Dns endpoints return an error")
		time.sleep(60)
		r = requests.get("https://endpoints.hexanyn.fr/dns.php?action=merge")
		if r.status_code == 200:
			self.output(r.text)
		else:
			self.output("Dns endpoints return an error")
	
	def grub(self):
		if (len(self.args) <= 0 or
			(len(self.args) >= 2 and not self.args[1].isnumeric())):
			self.output('Usage: `!grub <NAME> [#ID]`')
		else:
			devices = self.get_dhcpd()
			name = self.args[0]
			number = self.args[1] if len(self.args) >= 2 else False
			device = False
			for addr in devices:
				if devices[addr]['name'] == name:
					device = devices[addr]
					break
			if device:
				params = {'action': 'get' if not number else 'set'}
				if params['action'] == 'set':
					params['id'] = self.args[1]
				r = requests.get("http://{}:42666".format(device['addr']), params=params, timeout=3)
				self.output('```' + r.text + '```' if params['action'] == 'get' else 'Rebooting')
			else:
				self.output('Unknown device :(')
	
	def nmap(self):
		params = {'command': ' '.join(self.args)}
		self.output("Launching command `nmap {}`".format(params['command']))
		r = requests.get('https://endpoints.hexanyn.fr/nmap.php', params=params)
		self.output('```' + r.text + '```')

	def shutdown(self):
		if len(self.args) <= 0:
			self.output('Usage: `!shutdown <NAME>`')
		else:
			devices = self.get_dhcpd()
			name = self.args[0]
			device = False
			for addr in devices:
				if devices[addr]['name'] == name:
					device = devices[addr]
					break
			if device:
				params = {'action': 'shutdown'}
				linux = False
				windows = False
				try:
					r = requests.get("http://{}:42666".format(device['addr']), params=params, timeout=3)
					linux = True
				except:
					self.output('Linux mode failed for {}'.format(device['host']))
#				if not linux:
#					try:
#						r = requests.get("https://endpoints.hexanyn.fr/win_shutdown.php?addr={}".format(device['addr']), params=params, timeout=3)
#						windows = True
#					except requests.exceptions.Timeout:
#						self.output('Windows mode failed for {}, sorry'.format(device['host']))
				if linux or windows:
					self.output('Device powered off')
			else:
				self.output('Unknown device :(')
			
	def ssh(self):
		if len(self.args) == 0:
			self.cur.execute("SELECT * FROM authorized_keys ORDER BY active DESC, name;");
			attachments = []
			f = open('/ssh/authorized_keys', 'w')
			for entry in self.cur.fetchall():
				attachments.append({
					'color': '#00ff00' if entry[3] else '#ff0000',
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
									'text': f"{entry[2]}"
								}
							]
						}
					]
				})
				if entry[3]:
					f.write('# ' + entry[1] + '\n')
					f.write(entry[0] + '\n\n')
			f.close()
			self.output('Saved ssh keys', attachments)
		elif self.args[0] in ["create", "add", "new"]:
			if len(self.args) < 3:
				self.output("Missing args")
			else:
				try:
					f_name = "/tmp/{}".format(datetime.datetime.now().timestamp())
					f = open(f_name, 'w')
					f.write(' '.join(self.args[2:]))
					f.close()
					finger = subprocess.check_output(['ssh-keygen', '-E', 'sha256', '-lf', f_name]).decode('utf-8')
					postgres_insert_query = """ INSERT INTO authorized_keys (name, key, fingerprint, active) VALUES (%s,%s,%s,True)"""
					record_to_insert = (self.args[1], ' '.join(self.args[2:]), finger)
					self.cur.execute(postgres_insert_query, record_to_insert)

					self.pg.commit()
					self.args = []
					self.ssh()

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
					postgres_insert_query = """ DELETE FROM authorized_keys WHERE name=%s """
					records = []
					for arg in self.args[1:]:
						records.append([arg])
					self.cur.executemany(postgres_insert_query, records)

					self.pg.commit()
					self.args = []
					self.ssh()

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
					postgres_insert_query = """ UPDATE authorized_keys SET active=True WHERE active=False AND name=%s """
					records = []
					for arg in self.args[1:]:
						records.append([arg])
					self.cur.executemany(postgres_insert_query, records)

					self.pg.commit()
					self.args = []
					self.ssh()

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
					postgres_insert_query = """ UPDATE authorized_keys SET active=False WHERE active=True AND name=%s """
					records = []
					for arg in self.args[1:]:
						records.append([arg])
					self.cur.executemany(postgres_insert_query, records)

					self.pg.commit()
					self.args = []
					self.ssh()

				except (Exception, psycopg2.Error) as error:
					self.output("An error occured when updating")
					print(error)
					if(self.pg):
						self.pg.rollback()
		

	
	def help(self):
		self.output("""
`   !who    ` - Show devices connected
`   !dhcp   ` - Show dhcpd configuration (static address)
`!dhcp_sync ` - Synchronize device' names with dhcpd config
`  !leases  ` - Show active dhcp leases
`  !ports   ` - Show port forward
`   !mac    ` - Show whitelisted mac address
` !mac_sync ` - Synchronize hotspot with active devices in database
`  !mac_db  ` - Manage database
		Usage: `!mac_db [<create|remove|active|disable> <NAME> [MacAddr]]`
` !db_sync  ` - Synchronize device' names with mac_db
`!names_sync` - launch a db_sync then a dhcp_sync
`   !wake   ` - Turn on device
` !dns_sync ` - Update dns with dhcp names (DHCP.home)
`   !grub   ` - Grub reboot ;)
` !shutdown ` - Power off device
`   !nmap   ` - Launch an nmap command
`   !ssh    ` - Manage ssh keys
		Usage: `!ssh [<create|remove|active|disable> <NAME> [public key]]`
`   !help   ` - Display this help
		""")
	
	def dispatch(self):
		try:
			if   self.cmd == "who":			self.devices()
			elif self.cmd == "dhcp":		self.dhcp()
			elif self.cmd == "dhcp_sync":	self.dhcp_sync()
			elif self.cmd == "leases":		self.leases()
			elif self.cmd == "ports":		self.ports()
			elif self.cmd == "mac":			self.mac()
			elif self.cmd == "mac_sync":	self.mac_sync()
			elif self.cmd == "mac_db":		self.mac_db()
			elif self.cmd == "db_sync":		self.db_sync()
			elif self.cmd == "names_sync":	self.names_sync()
			elif self.cmd == "wake":		self.wake()
			elif self.cmd == "dns_sync":	self.dns_sync()
			elif self.cmd == "grub":		self.grub()
			elif self.cmd == "nmap":		self.nmap()
			elif self.cmd == "shutdown":	self.shutdown()
			elif self.cmd == "ssh":			self.ssh()
			elif self.cmd == "help":		self.help()
			elif self.cmd == "info":		self.help()
		except Exception as e:
			self.output("An error occured, please try again later")
			logging.error(e)
	
	def run(self, **event):
		self.event = event
		self.data = self.event["data"]
		if self.is_for_me() == True:
			self.parse_line(self.line)
			thread = Thread(target = self.dispatch)
			thread.start()

if __name__ == "__main__":
	box = boxbot()
