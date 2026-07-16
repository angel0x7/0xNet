package nettools

import (
	"fmt"
	"net"
	"os"
	"sort"
	"time"
)

// HopResult regroupe les mesures effectuées pour un saut (TTL) donné :
// adresse répondant, latences par sonde, taux de perte.
type HopResult struct {
	TTL      int
	Addr     string // "" si aucune sonde n'a répondu à ce saut
	RTTs     []time.Duration
	Probes   int
	Reached  bool // true si ce saut est la destination finale
}

// AvgRTT retourne la latence moyenne du saut (0 si aucune réponse).
func (h HopResult) AvgRTT() time.Duration {
	if len(h.RTTs) == 0 {
		return 0
	}
	var sum time.Duration
	for _, r := range h.RTTs {
		sum += r
	}
	return sum / time.Duration(len(h.RTTs))
}

// LossPercent retourne le pourcentage de sondes sans réponse pour ce saut.
func (h HopResult) LossPercent() float64 {
	if h.Probes == 0 {
		return 0
	}
	return 100 * float64(h.Probes-len(h.RTTs)) / float64(h.Probes)
}

// Traceroute effectue un traceroute ICMP classique : envoi de probes avec
// un TTL croissant (1..maxHops), interprétation des réponses "Time
// Exceeded" (saut intermédiaire) et "Echo Reply" (destination atteinte).
// S'arrête dès que la destination répond, ou après maxHops sauts sans
// réponse. probesPerHop sondes sont envoyées à chaque saut pour donner une
// mesure de perte/latence exploitable (comme un traceroute professionnel).
func Traceroute(host string, maxHops, probesPerHop int, timeout time.Duration) ([]HopResult, error) {
	dst, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return nil, fmt.Errorf("résolution de %q échouée: %w", host, err)
	}

	pconn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("ouverture socket ICMP échouée (droits root/CAP_NET_RAW ou Administrateur requis): %w", err)
	}
	defer pconn.Close()

	ipConn, ok := pconn.(*net.IPConn)
	if !ok {
		return nil, fmt.Errorf("type de connexion inattendu")
	}
	rawConn, err := ipConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("accès bas niveau au socket échoué: %w", err)
	}

	id := uint16(os.Getpid() & 0xffff)
	var hops []HopResult

	for ttl := 1; ttl <= maxHops; ttl++ {
		if err := setTTL(rawConn, ttl); err != nil {
			return hops, fmt.Errorf("réglage TTL=%d échoué: %w", ttl, err)
		}

		hop := HopResult{TTL: ttl, Probes: probesPerHop}
		reached := false

		for probe := 0; probe < probesPerHop; probe++ {
			seq := uint16(ttl*1000 + probe)
			msg := buildEchoRequest(id, seq, []byte("0xNetAdmin-trace"))

			start := time.Now()
			if _, err := pconn.WriteTo(msg, dst); err != nil {
				continue
			}
			rtt, from, matched := waitForHopReply(pconn, id, seq, timeout)
			if !matched {
				continue
			}
			hop.RTTs = append(hop.RTTs, rtt)
			if hop.Addr == "" {
				hop.Addr = from
			}
			if from == dst.String() {
				reached = true
			}
			_ = start
		}

		hop.Reached = reached
		hops = append(hops, hop)
		if reached {
			break
		}
	}

	return hops, nil
}

// waitForHopReply attend soit un Echo Reply de la destination finale, soit
// un Time Exceeded / Destination Unreachable d'un routeur intermédiaire,
// à condition que l'ID/Seq corresponde bien à notre sonde.
func waitForHopReply(conn net.PacketConn, id, seq uint16, timeout time.Duration) (time.Duration, string, bool) {
	start := time.Now()
	deadline := start.Add(timeout)
	buf := make([]byte, 1500)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, "", false
		}
		conn.SetReadDeadline(time.Now().Add(remaining))
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, "", false
		}
		m, ok := parseICMPv4(buf[:n])
		if !ok || m.ID != id || m.Seq != seq {
			continue
		}
		switch m.Type {
		case icmpEchoReply, icmpTimeExceeded, icmpDestUnreachable:
			return time.Since(start), peer.String(), true
		}
	}
}

// PrintTraceroute affiche le résultat dans un format lisible façon
// traceroute professionnel : un saut par ligne, latence min/avg/max, perte.
func PrintTraceroute(host string, hops []HopResult) {
	fmt.Printf("Traceroute vers %s, %d sauts max\n\n", host, len(hops))
	for _, h := range hops {
		addr := h.Addr
		if addr == "" {
			addr = "* * *"
		}
		if len(h.RTTs) == 0 {
			fmt.Printf("%2d  %-18s  perte=100%%  (aucune réponse)\n", h.TTL, addr)
			continue
		}
		sorted := append([]time.Duration{}, h.RTTs...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		min, max := sorted[0], sorted[len(sorted)-1]
		tag := ""
		if h.Reached {
			tag = "  <-- destination atteinte"
		}
		fmt.Printf("%2d  %-18s  min=%-8s avg=%-8s max=%-8s perte=%.0f%%%s\n",
			h.TTL, addr, min.Round(time.Microsecond), h.AvgRTT().Round(time.Microsecond),
			max.Round(time.Microsecond), h.LossPercent(), tag)
	}
}
