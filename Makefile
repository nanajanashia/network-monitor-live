run:
	sudo go run .

build:
	go build -o network-monitor .

install: build
	sudo cp network-monitor /usr/local/bin/
	sudo mkdir -p /etc/network-monitor
	sudo cp .env /etc/network-monitor/.env
	sudo cp network-monitor.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable network-monitor

start:
	sudo systemctl start network-monitor

stop:
	sudo systemctl stop network-monitor

status:
	sudo systemctl status network-monitor

logs:
	sudo journalctl -u network-monitor -f

uninstall:
	sudo systemctl stop network-monitor
	sudo systemctl disable network-monitor
	sudo rm -f /etc/systemd/system/network-monitor.service
	sudo rm -f /usr/local/bin/network-monitor
	sudo rm -rf /etc/network-monitor
	sudo systemctl daemon-reload


