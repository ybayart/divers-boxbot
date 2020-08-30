#!/usr/bin/python3
# -*- coding: latin-1 -*-

import requests, json, slack, os, subprocess, isc_dhcp_leases, timeago, datetime
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter
from utils import *

class boxbot:
	def __init__(self):
		self.bot_token = os.environ.get('SLACK_TOKEN')
		self.bot = slack.RTMClient(token=self.bot_token)
		self.client = slack.WebClient(self.bot_token)
		self.private_channel = os.environ.get('SLACK_CHANNEL')
		self.ensure_slack()
		self.session = requests.session()
		self.uri = "http://{}/ws".format(os.environ.get('BOX_IP'))
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
	
	def request(self, payload={}):
		r = self.session.post('http://192.168.1.254/ws', headers=self.headers['data'], json=payload).json()
		if r['status'] == None:
			r = self.session.post(self.uri, headers=self.headers['auth'], json=self.auth_payload).json()
			if r['status'] != 0:
				return False
			else:
				self.headers['data']['X-Context'] = r['data']['contextID']
				return self.request(payload)
		else:
			return r['status']

	def unable_fetch(self, out=False):
		self.output("Unable to retrieve datas...")
		if out != False: self.output(r)
	
	def devices(self):
		payload = {'service': 'Devices', 'method': 'get', 'parameters': {'expression': {'ETHERNET': 'not interface and not self and eth and .Active==true', 'WIFI': 'not interface and not self and wifi and .Active==true'}}}
		r = self.request(payload)
		if not r:
			self.unable_fetch()
		else:
			attachments = []
			leases = isc_dhcp_leases.IscDhcpLeases('/data/dhcp.leases').get_current()
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

	def ports(self):
		payload = {'service': 'Firewall', 'method': 'getPortForwarding', 'parameters': {'origin': 'webui'}}
		r = self.request(payload)
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
	
	def help(self):
		self.output("""
` !who ` - Show devices connected
`!ports` - Show port forward
`!help ` - Display this help
		""")
	
	def dispatch(self):
		if   self.cmd == "who":		self.devices()
		elif self.cmd == "ports":	self.ports()
		elif self.cmd == "help":	self.help()
	
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
