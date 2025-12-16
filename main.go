package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var currentlyAnalyzing sync.Map

type IPPacket struct {
	PacketNumber   int    `json:"packet_number"`
	TotalBytes     int    `json:"total_bytes"`
	Version        uint8  `json:"version"`
	TotalLength    uint16 `json:"total_length"`
	Flags          uint8  `json:"flags"`
	TTL            uint8  `json:"ttl"`
	Protocol       uint8  `json:"protocol"`
	HeaderChecksum uint16 `json:"header_checksum"`
	SourceIP       string `json:"source_ip"`
	DestinationIP  string `json:"destination_ip"`
}

type VirusTotalResult struct {
	IP         string
	Malicious  int
	Suspicious int
	Harmless   int
	Undetected int
	ScanDate   string
}

type VirusTotalResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			LastAnalysisDate int64 `json:"last_analysis_date"`
		} `json:"attributes"`
	} `json:"data"`
}

type Config struct {
	NIC           string
	APIKey        string
	VirusTotalURL string
	DBURL         string
}

func loadConfig(configPath string) *Config {
	err := godotenv.Load(configPath)
	if err != nil {
		log.Fatalf("Error loading config file: %s", configPath)
	}

	return &Config{
		NIC:           os.Getenv("NIC"),
		APIKey:        os.Getenv("APIKEY"),
		VirusTotalURL: os.Getenv("VIRUSTOTAL_URL"),
		DBURL:         os.Getenv("DB_URL"),
	}
}

func connectDB(dbURL string) *sql.DB {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Error opening database: ", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Error connecting to database: ", err)
	}

	fmt.Println("Connected to database")
	return db
}

func main() {
	configPath := flag.String("c", ".env", "path to config file")
	flag.StringVar(configPath, "config", ".env", "path to config file")
	flag.Parse()

	config := loadConfig(*configPath)

	db := connectDB(config.DBURL)
	defer db.Close()

	handle, err := pcap.OpenLive(config.NIC, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	linkType := handle.LinkType()
	packetSource := gopacket.NewPacketSource(handle, linkType)

	fmt.Println("Starting continuous packet capture...")
	packetNumber := 0

	for packet := range packetSource.Packets() {
		packetNumber++
		ipPacket := parseIPHeader(packetNumber, packet.Data(), linkType)
		if ipPacket == nil {
			continue
		}

		if isPrivateIP(ipPacket.DestinationIP) {
			continue
		}

		go processPacket(ipPacket, db, config)
	}

	var results []VirusTotalResult
	_ = results
	_ = config
}

func processPacket(packet *IPPacket, db *sql.DB, config *Config) {
	// Check if IP is currently being analyzed
	if _, analyzing := currentlyAnalyzing.LoadOrStore(packet.DestinationIP, true); analyzing {
		return
	}
	defer currentlyAnalyzing.Delete(packet.DestinationIP)

	var recentlyChecked bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM packet_info
			WHERE destination_ip = $1
			AND checked_at > NOW() - INTERVAL '24 hours'
		)`, packet.DestinationIP).Scan(&recentlyChecked)
	if err != nil {
		fmt.Printf("Error checking destination IP: %v\n", err)
		return
	}

	if recentlyChecked {
		return
	}

	result := checkIPOnVirusTotal(packet.DestinationIP, config.APIKey, config.VirusTotalURL)
	if result == nil {
		fmt.Printf("Failed to check IP %s on VirusTotal\n", packet.DestinationIP)
		return
	}

	_, err = db.Exec(`
		INSERT INTO packet_info (
			version, total_length, flags, ttl, protocol, header_checksum,
			source_ip, destination_ip, malicious, suspicious, harmless,
			undetected, scan_date, checked_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())`,
		fmt.Sprintf("%d", packet.Version),
		packet.TotalLength,
		fmt.Sprintf("%d", packet.Flags),
		packet.TTL,
		fmt.Sprintf("%d", packet.Protocol),
		packet.HeaderChecksum,
		packet.SourceIP,
		packet.DestinationIP,
		result.Malicious,
		result.Suspicious,
		result.Harmless,
		result.Undetected,
		result.ScanDate,
	)
	if err != nil {
		fmt.Printf("Error inserting packet info: %v\n", err)
		return
	}

	fmt.Printf("Inserted: %s (Malicious: %d, Suspicious: %d)\n",
		packet.DestinationIP, result.Malicious, result.Suspicious)
}

func parseIPHeader(packetNumber int, packetData []byte, linkType layers.LinkType) *IPPacket {
	packet := gopacket.NewPacket(packetData, linkType, gopacket.Default)

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		return &IPPacket{
			PacketNumber:   packetNumber,
			TotalBytes:     len(packetData),
			Version:        4,
			TotalLength:    ipv4.Length,
			Flags:          uint8(ipv4.Flags),
			TTL:            ipv4.TTL,
			Protocol:       uint8(ipv4.Protocol),
			HeaderChecksum: ipv4.Checksum,
			SourceIP:       ipv4.SrcIP.String(),
			DestinationIP:  ipv4.DstIP.String(),
		}
	}

	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		return &IPPacket{
			PacketNumber:   packetNumber,
			TotalBytes:     len(packetData),
			Version:        6,
			TotalLength:    ipv6.Length,
			Flags:          0,
			TTL:            ipv6.HopLimit,
			Protocol:       uint8(ipv6.NextHeader),
			HeaderChecksum: 0,
			SourceIP:       ipv6.SrcIP.String(),
			DestinationIP:  ipv6.DstIP.String(),
		}
	}

	return nil
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func checkIPOnVirusTotal(ip string, apiKey string, baseURL string) *VirusTotalResult {
	url := fmt.Sprintf("%s/%s", baseURL, ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request for %s: %v\n", ip, err)
		return nil
	}

	req.Header.Set("x-apikey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error checking %s: %v\n", ip, err)
		return nil
	}
	defer resp.Body.Close()

	var response VirusTotalResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		fmt.Printf("Error parsing JSON for %s: %v\n", ip, err)
		return nil
	}

	stats := response.Data.Attributes.LastAnalysisStats
	scanDate := time.Unix(response.Data.Attributes.LastAnalysisDate, 0).Format("2006-01-02")

	return &VirusTotalResult{
		IP:         ip,
		Malicious:  stats.Malicious,
		Suspicious: stats.Suspicious,
		Harmless:   stats.Harmless,
		Undetected: stats.Undetected,
		ScanDate:   scanDate,
	}
}
