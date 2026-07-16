//go:build linux

package sniffer

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

const ethPAll = 0x0003 // ETH_P_ALL

// htons convertit un uint16 host-order en network-order (big endian).
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | (i>>8)&0x00ff
}

// Sniffer (Linux) encapsule un raw socket AF_PACKET.
type Sniffer struct {
	fd      int
	opts    Options
	stats   Stats
	stopped int32
	pcap    *PCAPWriter
	flows   map[FlowKey]*FlowStats
}

// New ouvre un raw socket AF_PACKET écoutant ETH_P_ALL, lié à l'interface
// donnée si précisée. Nécessite CAP_NET_RAW (root en général).
func New(opts Options) (*Sniffer, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("ouverture raw socket échouée (%s): %w", privilegeHint(), err)
	}

	if opts.Iface != "" {
		ifi, err := net.InterfaceByName(opts.Iface)
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("interface %q introuvable: %w", opts.Iface, err)
		}
		sll := syscall.SockaddrLinklayer{
			Protocol: htons(ethPAll),
			Ifindex:  ifi.Index,
		}
		if err := syscall.Bind(fd, &sll); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("bind sur %q échoué: %w", opts.Iface, err)
		}
	}

	// timeout de lecture pour pouvoir revérifier régulièrement deadline/stop
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})

	s := &Sniffer{fd: fd, opts: opts, flows: make(map[FlowKey]*FlowStats)}

	if opts.PCAPFile != "" {
		w, err := NewPCAPWriter(opts.PCAPFile, DLTEthernet)
		if err != nil {
			syscall.Close(fd)
			return nil, err
		}
		s.pcap = w
	}

	return s, nil
}

// Close libère le socket et referme le fichier pcap éventuel.
func (s *Sniffer) Close() error {
	if s.pcap != nil {
		s.pcap.Close()
	}
	return syscall.Close(s.fd)
}

// Stats retourne une copie des compteurs actuels.
func (s *Sniffer) Stats() Stats {
	return s.stats
}

// Run démarre la boucle de capture. En mode normal, affiche chaque paquet
// retenu par le filtre ; en mode -flows, agrège par 5-tuple et affiche la
// table en fin de capture. S'arrête sur Ctrl+C, MaxPackets, ou Duration.
func (s *Sniffer) Run() error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	var deadline time.Time
	if s.opts.Duration > 0 {
		deadline = time.Now().Add(s.opts.Duration)
	}

	buf := make([]byte, 65536)

	go func() {
		<-sigCh
		atomic.StoreInt32(&s.stopped, 1)
	}()

	for atomic.LoadInt32(&s.stopped) == 0 {
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}
		if s.opts.MaxPackets > 0 && int(s.stats.Total) >= s.opts.MaxPackets {
			break
		}

		n, _, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			return fmt.Errorf("erreur de lecture socket: %w", err)
		}
		if n == 0 {
			continue
		}

		pkt := decodeEthernet(buf[:n])
		if pkt == nil {
			continue
		}

		s.stats.update(pkt, n)

		if !s.opts.Filter.matches(pkt) {
			continue
		}

		if s.pcap != nil {
			s.pcap.WritePacket(buf[:n])
		}

		if s.opts.AggregateFlows {
			updateFlow(s.flows, pkt, n)
		} else {
			printPacket(s.stats.Total, pkt, s.opts.Verbose)
		}
	}

	if s.opts.AggregateFlows {
		printFlows(s.flows)
	}

	return nil
}
