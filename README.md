BoxBot is a Slack bot & a crowler for Livebox 5 & OpenWRT

Firstly, you need to create an boxbot.env file
```
# TIMEZONE
TZ: Europe/Paris

# LIVEBOX CONFIGURATION
BOX_USER: user
BOX_PASS: password
BOX_IP: 192.168.0.1

# OPENWRT 1 CONFIGURATION
ROUTER_USER: user
ROUTER_PASS: password
ROUTER_IP: 192.168.0.2

# OPENWRT 2 CONFIGURATION
RPI_USER: user
RPI_PASS: password
RPI_IP: 192.168.0.3

# DATABASE PASSWORD
PG_PASS: some_password

# SLACK CONFIGURATION
SLACK_TOKEN: xorb-...
SLACK_CHANNEL:
```

After, just use `docker-compose up -d` to deploy
