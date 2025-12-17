# ქსელური ნაკადის რეალურ დროში მონიტორინგი

ქსელური ნაკადის რეალურ დროში მონიტორინგის, ანალიზისა და უსაფრთხოების სისტემა.

## წინაპირობები

- Go 1.21+
- PostgreSQL
- VirusTotal API key
- libpcap (`apt-get install libpcap-dev`)
- ca-certificates (`apt-get install ca-certificates`) - თუ SSL შეცდომებია

## გაშვება

### 1. ბაზა

ბაზის შექმნა თავისი ცხრილით:

```bash
psql -U postgres -f schema.sql
```

### 2. კონფიგურაცია

დააკოპირეთ `.env.example` ფაილი `.env`-ად და შეავსეთ თქვენი მონაცემებით:

```env
cp .env.example .env
```

შექმენით დირექტორია ლოგებისთვის:

```bash
sudo mkdir -p /var/log/network-monitor
```

### 3. დააინსტალირეთ ბიბლიოთეკები

```bash
go mod tidy
```

## გაშვება

### ლოკალურად

```bash
make run
```

### სერვერზე

```bash
make build
sudo ./network-monitor -c .env
```

## Systemd 

```bash
make install   # build, install, enable service
make start     # start service
make stop      # stop service
make status    # check status
make logs      # view logs
make uninstall # remove service
```

## ლოგები

ლოგები ჩაიწერება `LOG_FILE` -ში მითითებულ მისამართზე.

ამ ეტაპზე დაილოგება მხოლოთ საეჭვო ip მისამართები.

მაგალითი:

```
2025-12-16 12:30:45 [INFO] Application started
2025-12-16 12:30:45 [INFO] Packet capture started on en0
2025-12-16 12:31:00 [ERROR] VirusTotal API error for 1.2.3.4: status 429
2025-12-16 12:31:05 [ALERT] Threat detected: 5.6.7.8 (Malicious: 3, Suspicious: 1)
```
