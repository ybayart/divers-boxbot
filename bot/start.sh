if [ ! "$NOUPDATE" == "1" ]
then
	pip3 install -r /data/requirements.txt
fi
python3 /data/boxbot.py
