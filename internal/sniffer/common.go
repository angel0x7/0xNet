// Package sniffer implémente une capture de paquets bas niveau et son
// décodage couche par couche, aligné sur le modèle OSI :
//
//	L2 : Ethernet (+ ARP)   — Linux uniquement (raw socket AF_PACKET)
//	L3 : IPv4 / IPv6 / ICMP — Linux et Windows
//	L4 : TCP / UDP          — Linux et Windows
//	L7 : détection applicative par port bien connu
//
// La capture elle-même diffère par OS (sniffer_linux.go / sniffer_windows.go)
// car il n'existe pas d'API bas niveau portable équivalente à AF_PACKET sous
// Windows. Ce fichier ne contient que le décodage, commun aux deux capteurs.
package sniffer

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"time"
)

const (
	ethTypeIPv4 = 0x0800
	ethTypeARP  = 0x0806
	ethTypeIPv6 = 0x86DD

	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// Options configure une session de capture.
type Options struct {
	Iface          string        // interface à écouter, "" = auto
	MaxPackets     int           // 0 = illimité
	Duration       time.Duration // 0 = illimité
	Filter         Filter
	Verbose        bool   // affiche le détail du payload
	AggregateFlows bool   // mode agrégation 5-tuple au lieu de paquet-par-paquet
	PCAPFile       string // si non vide, écrit un fichier .pcap standard
}

// Filter permet de restreindre la capture (protocole / port).
type Filter struct {
	Proto string // "tcp", "udp", "icmp", "arp", "" = tout
	Port  int    // 0 = tout port
}

// Stats agrège les compteurs de capture.
type Stats struct {
	Total uint64
	ARP   uint64
	IPv4  uint64
	IPv6  uint64
	TCP   uint64
	UDP   uint64
	ICMP  uint64
	Other uint64
	Bytes uint64
}

func (s *Stats) update(p *Packet, n int) {
	s.Total++
	s.Bytes += uint64(n)
	switch p.EtherType {
	case ethTypeARP:
		s.ARP++
	case ethTypeIPv4:
		s.IPv4++
	case ethTypeIPv6:
		s.IPv6++
	default:
		s.Other++
		return
	}
	switch {
	case p.TCP != nil:
		s.TCP++
	case p.UDP != nil:
		s.UDP++
	case p.ICMP != nil:
		s.ICMP++
	}
}

func (f Filter) matches(p *Packet) bool {
	switch f.Proto {
	case "arp":
		if p.EtherType != ethTypeARP {
			return false
		}
	case "tcp":
		if p.TCP == nil {
			return false
		}
	case "udp":
		if p.UDP == nil {
			return false
		}
	case "icmp":
		if p.ICMP == nil {
			return false
		}
	}
	if f.Port != 0 {
		switch {
		case p.TCP != nil:
			if int(p.TCP.SrcPort) != f.Port && int(p.TCP.DstPort) != f.Port {
				return false
			}
		case p.UDP != nil:
			if int(p.UDP.SrcPort) != f.Port && int(p.UDP.DstPort) != f.Port {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ---- Structures de décodage ----

// EthHeader : en-tête Ethernet L2 (Linux uniquement — vide sous Windows).
type EthHeader struct {
	DstMAC, SrcMAC net.HardwareAddr
}

// ARPHeader : requête/réponse ARP (Linux uniquement).
type ARPHeader struct {
	Operation uint16 // 1=request, 2=reply
	SenderMAC net.HardwareAddr
	SenderIP  net.IP
	TargetMAC net.HardwareAddr
	TargetIP  net.IP
}

// IPv4Header : en-tête L3 IPv4.
type IPv4Header struct {
	Version, IHL int
	TOS          byte
	TotalLength  uint16
	TTL          byte
	Protocol     byte
	SrcIP, DstIP net.IP
}

// IPv6Header : en-tête L3 IPv6 (simplifié, pas d'extension headers).
type IPv6Header struct {
	TrafficClass byte
	NextHeader   byte
	HopLimit     byte
	SrcIP, DstIP net.IP
}

// TCPHeader : en-tête L4 TCP.
type TCPHeader struct {
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            string
	Window           uint16
}

// UDPHeader : en-tête L4 UDP.
type UDPHeader struct {
	SrcPort, DstPort uint16
	Length           uint16
}

// ICMPHeader : en-tête ICMP.
type ICMPHeader struct {
	Type, Code byte
}

// Packet regroupe le décodage multi-couches d'une trame/paquet capturé.
// Sous Windows, Eth/ARP restent à zéro car la capture démarre au niveau IP.
type Packet struct {
	Eth         EthHeader
	EtherType   uint16
	ARP         *ARPHeader
	IPv4        *IPv4Header
	IPv6        *IPv6Header
	TCP         *TCPHeader
	UDP         *UDPHeader
	ICMP        *ICMPHeader
	AppProtocol string
	PayloadLen  int
}

// decodeEthernet décode une trame complète à partir de l'en-tête Ethernet
// (utilisé par le capteur Linux, AF_PACKET).
func decodeEthernet(raw []byte) *Packet {
	if len(raw) < 14 {
		return nil
	}
	p := &Packet{
		Eth: EthHeader{
			DstMAC: net.HardwareAddr(raw[0:6]),
			SrcMAC: net.HardwareAddr(raw[6:12]),
		},
		EtherType: binary.BigEndian.Uint16(raw[12:14]),
	}

	payload := raw[14:]

	switch p.EtherType {
	case ethTypeARP:
		p.ARP = decodeARP(payload)
	case ethTypeIPv4:
		decodeIPv4(payload, p)
	case ethTypeIPv6:
		decodeIPv6(payload, p)
	}
	return p
}

// decodeIPPacket décode un paquet démarrant directement à l'en-tête IP
// (utilisé par le capteur Windows, raw socket SIO_RCVALL — pas d'Ethernet).
func decodeIPPacket(raw []byte) *Packet {
	if len(raw) < 1 {
		return nil
	}
	version := raw[0] >> 4
	p := &Packet{}
	switch version {
	case 4:
		p.EtherType = ethTypeIPv4
		decodeIPv4(raw, p)
	case 6:
		p.EtherType = ethTypeIPv6
		decodeIPv6(raw, p)
	default:
		return nil
	}
	return p
}

func decodeARP(b []byte) *ARPHeader {
	if len(b) < 28 {
		return nil
	}
	return &ARPHeader{
		Operation: binary.BigEndian.Uint16(b[6:8]),
		SenderMAC: net.HardwareAddr(b[8:14]),
		SenderIP:  net.IP(b[14:18]),
		TargetMAC: net.HardwareAddr(b[18:24]),
		TargetIP:  net.IP(b[24:28]),
	}
}

func decodeIPv4(b []byte, p *Packet) {
	if len(b) < 20 {
		return
	}
	ihl := int(b[0]&0x0F) * 4
	if ihl < 20 || len(b) < ihl {
		ihl = 20
	}
	hdr := &IPv4Header{
		Version:     int(b[0] >> 4),
		IHL:         ihl,
		TOS:         b[1],
		TotalLength: binary.BigEndian.Uint16(b[2:4]),
		TTL:         b[8],
		Protocol:    b[9],
		SrcIP:       net.IP(b[12:16]),
		DstIP:       net.IP(b[16:20]),
	}
	p.IPv4 = hdr

	if len(b) <= ihl {
		return
	}
	decodeTransport(hdr.Protocol, b[ihl:], p)
}

func decodeIPv6(b []byte, p *Packet) {
	if len(b) < 40 {
		return
	}
	hdr := &IPv6Header{
		TrafficClass: (b[0]&0x0F)<<4 | b[1]>>4,
		NextHeader:   b[6],
		HopLimit:     b[7],
		SrcIP:        net.IP(b[8:24]),
		DstIP:        net.IP(b[24:40]),
	}
	p.IPv6 = hdr
	if len(b) > 40 {
		decodeTransport(hdr.NextHeader, b[40:], p)
	}
}

func decodeTransport(proto byte, b []byte, p *Packet) {
	switch proto {
	case protoTCP:
		if len(b) < 20 {
			return
		}
		offset := int(b[12]>>4) * 4
		p.TCP = &TCPHeader{
			SrcPort: binary.BigEndian.Uint16(b[0:2]),
			DstPort: binary.BigEndian.Uint16(b[2:4]),
			Seq:     binary.BigEndian.Uint32(b[4:8]),
			Ack:     binary.BigEndian.Uint32(b[8:12]),
			Flags:   tcpFlagsString(b[13]),
			Window:  binary.BigEndian.Uint16(b[14:16]),
		}
		if offset > 0 && offset < len(b) {
			p.PayloadLen = len(b) - offset
		}
		p.AppProtocol = detectApp(p.TCP.SrcPort, p.TCP.DstPort)
	case protoUDP:
		if len(b) < 8 {
			return
		}
		p.UDP = &UDPHeader{
			SrcPort: binary.BigEndian.Uint16(b[0:2]),
			DstPort: binary.BigEndian.Uint16(b[2:4]),
			Length:  binary.BigEndian.Uint16(b[4:6]),
		}
		p.PayloadLen = len(b) - 8
		p.AppProtocol = detectApp(p.UDP.SrcPort, p.UDP.DstPort)
	case protoICMP:
		if len(b) < 2 {
			return
		}
		p.ICMP = &ICMPHeader{Type: b[0], Code: b[1]}
	}
}

func tcpFlagsString(f byte) string {
	var flags string
	if f&0x01 != 0 {
		flags += "FIN "
	}
	if f&0x02 != 0 {
		flags += "SYN "
	}
	if f&0x04 != 0 {
		flags += "RST "
	}
	if f&0x08 != 0 {
		flags += "PSH "
	}
	if f&0x10 != 0 {
		flags += "ACK "
	}
	if f&0x20 != 0 {
		flags += "URG "
	}
	if flags == "" {
		return "-"
	}
	return flags[:len(flags)-1]
}

// detectApp fait une détection L7 best-effort par port bien connu.
func detectApp(src, dst uint16) string {
	wellKnown := map[uint16]string{
		20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
		53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
		110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 179: "BGP",
		389: "LDAP", 443: "HTTPS", 445: "SMB", 500: "IKE/IPsec",
		514: "Syslog", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
		1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
		5432: "PostgreSQL", 8080: "HTTP-ALT",
	}
	if name, ok := wellKnown[dst]; ok {
		return name
	}
	if name, ok := wellKnown[src]; ok {
		return name
	}
	return "-"
}

// ---- Agrégation de flux (5-tuple) ----

// FlowKey identifie un flux par le 5-tuple classique. Proto vaut "tcp",
// "udp" ou "icmp"/"other" pour les paquets sans port.
type FlowKey struct {
	Proto            string
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
}

// FlowStats agrège les compteurs d'un flux au fil de la capture.
type FlowStats struct {
	Packets  uint64
	Bytes    uint64
	First    time.Time
	Last     time.Time
}

// flowKeyFromPacket construit la clé de flux d'un paquet décodé, si
// applicable (IPv4/IPv6 uniquement). ok=false pour les trames non-IP (ARP...).
func flowKeyFromPacket(p *Packet) (FlowKey, bool) {
	var srcIP, dstIP string
	switch {
	case p.IPv4 != nil:
		srcIP, dstIP = p.IPv4.SrcIP.String(), p.IPv4.DstIP.String()
	case p.IPv6 != nil:
		srcIP, dstIP = p.IPv6.SrcIP.String(), p.IPv6.DstIP.String()
	default:
		return FlowKey{}, false
	}

	switch {
	case p.TCP != nil:
		return FlowKey{"tcp", srcIP, dstIP, p.TCP.SrcPort, p.TCP.DstPort}, true
	case p.UDP != nil:
		return FlowKey{"udp", srcIP, dstIP, p.UDP.SrcPort, p.UDP.DstPort}, true
	case p.ICMP != nil:
		return FlowKey{"icmp", srcIP, dstIP, 0, 0}, true
	default:
		return FlowKey{"other", srcIP, dstIP, 0, 0}, true
	}
}

// updateFlow met à jour (ou crée) l'entrée de flux correspondant au paquet.
func updateFlow(flows map[FlowKey]*FlowStats, p *Packet, n int) {
	key, ok := flowKeyFromPacket(p)
	if !ok {
		return
	}
	now := time.Now()
	fs, exists := flows[key]
	if !exists {
		fs = &FlowStats{First: now}
		flows[key] = fs
	}
	fs.Packets++
	fs.Bytes += uint64(n)
	fs.Last = now
}

// printFlows affiche la table de flux triée par volume décroissant —
// répond au besoin "qui parle à qui" plus lisible que le mode paquet par
// paquet pour un premier diagnostic.
func printFlows(flows map[FlowKey]*FlowStats) {
	type row struct {
		Key FlowKey
		FlowStats
	}
	rows := make([]row, 0, len(flows))
	for k, v := range flows {
		rows = append(rows, row{k, *v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Bytes > rows[j].Bytes })

	fmt.Printf("\n--- Flux agrégés (5-tuple), %d flux ---\n", len(rows))
	fmt.Printf("%-6s %-21s %-21s %10s %10s %10s\n", "PROTO", "SOURCE", "DESTINATION", "PAQUETS", "OCTETS", "DUREE")
	for _, r := range rows {
		src := r.Key.SrcIP
		dst := r.Key.DstIP
		if r.Key.SrcPort != 0 || r.Key.DstPort != 0 {
			src = fmt.Sprintf("%s:%d", r.Key.SrcIP, r.Key.SrcPort)
			dst = fmt.Sprintf("%s:%d", r.Key.DstIP, r.Key.DstPort)
		}
		dur := r.Last.Sub(r.First).Round(time.Millisecond)
		fmt.Printf("%-6s %-21s %-21s %10d %10d %10s\n", r.Key.Proto, src, dst, r.Packets, r.Bytes, dur)
	}
}

func printPacket(n uint64, p *Packet, verbose bool) {
	ts := time.Now().Format("15:04:05.000")

	switch {
	case p.ARP != nil:
		op := "REQUEST"
		if p.ARP.Operation == 2 {
			op = "REPLY"
		}
		fmt.Printf("[%s] #%-6d L2/ARP  %-7s who-has %-15s tell %-15s (%s -> %s)\n",
			ts, n, op, p.ARP.TargetIP, p.ARP.SenderIP, p.ARP.SenderMAC, p.ARP.TargetMAC)

	case p.IPv4 != nil && p.TCP != nil:
		fmt.Printf("[%s] #%-6d L3/L4   TCP  %-15s:%-5d -> %-15s:%-5d flags=[%s] ttl=%-3d len=%-5d app=%s\n",
			ts, n, p.IPv4.SrcIP, p.TCP.SrcPort, p.IPv4.DstIP, p.TCP.DstPort,
			p.TCP.Flags, p.IPv4.TTL, p.IPv4.TotalLength, p.AppProtocol)

	case p.IPv4 != nil && p.UDP != nil:
		fmt.Printf("[%s] #%-6d L3/L4   UDP  %-15s:%-5d -> %-15s:%-5d ttl=%-3d len=%-5d app=%s\n",
			ts, n, p.IPv4.SrcIP, p.UDP.SrcPort, p.IPv4.DstIP, p.UDP.DstPort,
			p.IPv4.TTL, p.UDP.Length, p.AppProtocol)

	case p.IPv4 != nil && p.ICMP != nil:
		fmt.Printf("[%s] #%-6d L3      ICMP %-15s -> %-15s type=%-3d code=%-3d ttl=%d\n",
			ts, n, p.IPv4.SrcIP, p.IPv4.DstIP, p.ICMP.Type, p.ICMP.Code, p.IPv4.TTL)

	case p.IPv4 != nil:
		fmt.Printf("[%s] #%-6d L3      IPv4 %-15s -> %-15s proto=%-3d ttl=%d\n",
			ts, n, p.IPv4.SrcIP, p.IPv4.DstIP, p.IPv4.Protocol, p.IPv4.TTL)

	case p.IPv6 != nil:
		fmt.Printf("[%s] #%-6d L3      IPv6 %-25s -> %-25s next=%-3d hlim=%d\n",
			ts, n, p.IPv6.SrcIP, p.IPv6.DstIP, p.IPv6.NextHeader, p.IPv6.HopLimit)

	default:
		fmt.Printf("[%s] #%-6d L2      EtherType=0x%04x %s -> %s\n",
			ts, n, p.EtherType, p.Eth.SrcMAC, p.Eth.DstMAC)
	}

	if verbose && p.PayloadLen > 0 {
		fmt.Printf("           payload: %d octets\n", p.PayloadLen)
	}
}

// isPrivilegeError donne un message d'aide homogène sur les deux OS quand
// l'ouverture du capteur échoue faute de droits suffisants.
func privilegeHint() string {
	return "Linux: relancer avec sudo ou CAP_NET_RAW. Windows: relancer l'invite de commandes en Administrateur, avec Npcap ou droits raw socket."
}
