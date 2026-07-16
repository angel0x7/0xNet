// Package nettools fournit des primitives réseau bas niveau en Go pur
// (aucune dépendance externe) : ping ICMP natif et traceroute, utilisés à
// la place des binaires système `ping`/`traceroute`/`tracert`.
//
// Nécessite les mêmes droits qu'un ping classique : root/CAP_NET_RAW sous
// Linux, invite Administrateur sous Windows (raw socket ICMP).
package nettools

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

// icmpMsg est la représentation décodée minimale d'un message ICMPv4 utile
// au ping/traceroute (Echo Reply, Time Exceeded, Destination Unreachable).
type icmpMsg struct {
	Type, Code byte
	ID, Seq    uint16
}

const (
	icmpEchoRequest       = 8
	icmpEchoReply         = 0
	icmpTimeExceeded      = 11
	icmpDestUnreachable   = 3
)

// PingResult est le résultat d'un ping ICMP unique.
type PingResult struct {
	RTT  time.Duration
	From string
}

// Ping envoie une requête ICMP Echo unique et attend la réponse. Retourne
// une erreur explicite si les droits sont insuffisants pour ouvrir un raw
// socket ICMP (root/CAP_NET_RAW sous Linux, Administrateur sous Windows).
func Ping(host string, timeout time.Duration) (PingResult, error) {
	dst, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return PingResult{}, fmt.Errorf("résolution de %q échouée: %w", host, err)
	}

	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return PingResult{}, fmt.Errorf("ouverture socket ICMP échouée (droits root/CAP_NET_RAW ou Administrateur requis): %w", err)
	}
	defer conn.Close()

	id := uint16(os.Getpid() & 0xffff)
	seq := uint16(1)
	msg := buildEchoRequest(id, seq, []byte("0xNetAdmin-ping"))

	start := time.Now()
	if _, err := conn.WriteTo(msg, dst); err != nil {
		return PingResult{}, fmt.Errorf("envoi ICMP échoué: %w", err)
	}

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 1500)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return PingResult{}, fmt.Errorf("timeout après %s", timeout)
		}
		conn.SetReadDeadline(time.Now().Add(remaining))
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return PingResult{}, fmt.Errorf("timeout après %s", timeout)
		}
		m, ok := parseICMPv4(buf[:n])
		if !ok || m.Type != icmpEchoReply || m.ID != id || m.Seq != seq {
			continue // paquet ICMP non lié à notre requête, on continue d'attendre
		}
		return PingResult{RTT: time.Since(start), From: peer.String()}, nil
	}
}

// buildEchoRequest construit un message ICMP Echo Request (type 8) avec
// somme de contrôle correcte.
func buildEchoRequest(id, seq uint16, payload []byte) []byte {
	msg := make([]byte, 8+len(payload))
	msg[0] = icmpEchoRequest
	msg[1] = 0 // code
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[8:], payload)
	cs := checksum(msg)
	binary.BigEndian.PutUint16(msg[2:4], cs)
	return msg
}

// checksum calcule la somme de contrôle Internet (RFC 1071) utilisée par
// ICMP/IP.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// stripIPHeaderIfPresent retire l'en-tête IPv4 d'un buffer si celui-ci en
// contient un (comportement variable des raw sockets ICMP selon l'OS :
// Linux et Windows peuvent inclure l'en-tête IP reçu, contrairement à
// d'autres piles). Détection par le nibble de version (0x4).
func stripIPHeaderIfPresent(b []byte) []byte {
	if len(b) < 1 {
		return b
	}
	version := b[0] >> 4
	if version == 4 {
		ihl := int(b[0]&0x0F) * 4
		if ihl >= 20 && len(b) > ihl {
			return b[ihl:]
		}
	}
	return b
}

// parseICMPv4 décode un message ICMPv4, en récupérant l'ID/Seq soit
// directement (Echo Reply/Request), soit depuis le datagramme original cité
// en payload (Time Exceeded / Destination Unreachable — cas du traceroute).
func parseICMPv4(raw []byte) (icmpMsg, bool) {
	b := stripIPHeaderIfPresent(raw)
	if len(b) < 8 {
		return icmpMsg{}, false
	}
	m := icmpMsg{Type: b[0], Code: b[1]}

	switch m.Type {
	case icmpEchoReply, icmpEchoRequest:
		m.ID = binary.BigEndian.Uint16(b[4:6])
		m.Seq = binary.BigEndian.Uint16(b[6:8])
	case icmpTimeExceeded, icmpDestUnreachable:
		// Les 8 premiers octets sont l'en-tête ICMP d'erreur, suivis de
		// l'en-tête IP du datagramme original + ses 8 premiers octets
		// (ici, notre propre requête ICMP Echo).
		inner := stripIPHeaderIfPresent(b[8:])
		if len(inner) >= 8 {
			m.ID = binary.BigEndian.Uint16(inner[4:6])
			m.Seq = binary.BigEndian.Uint16(inner[6:8])
		}
	}
	return m, true
}
