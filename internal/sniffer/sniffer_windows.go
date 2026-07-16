//go:build windows

// Sous Windows, deux moteurs de capture sont disponibles :
//
//  1. Npcap (wpcap.dll), s'il est installé : capture Ethernet complète
//     (ARP inclus), chargée dynamiquement (aucune dépendance de build).
//  2. Repli automatique : raw socket AF_INET + ioctl SIO_RCVALL, qui ne
//     fournit que les couches L3+ (pas d'Ethernet/ARP) mais ne nécessite
//     aucun logiciel tiers — c'est la limitation connue de l'API Winsock.
//
// Le choix se fait automatiquement à l'ouverture ; -no-npcap force le
// second mode même si Npcap est disponible.
package sniffer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	sioRCVALL = 0x98000001 // IOC_IN | IOC_VENDOR | 1
	rcvallOn  = uint32(1)

	// SO_RCVTIMEO n'est pas exposé par le package syscall standard pour
	// Windows (contrairement à Linux/BSD) ; valeur Winsock officielle.
	soRcvTimeoWindows = 0x1006
)

// Sniffer (Windows) encapsule soit un moteur Npcap (Ethernet complet), soit
// un raw socket AF_INET en mode SIO_RCVALL (IPv4 uniquement, repli).
type Sniffer struct {
	fd      syscall.Handle // utilisé seulement en mode raw socket (npcap == nil)
	npcap   *npcapEngine   // utilisé seulement en mode Npcap
	opts    Options
	stats   Stats
	stopped int32
	pcap    *PCAPWriter
	flows   map[FlowKey]*FlowStats
}

// New ouvre le meilleur moteur de capture disponible : Npcap si installé
// (sauf si opts.Iface commence par "!nocap!", utilisé en interne pour les
// tests), sinon raw socket SIO_RCVALL. Nécessite une invite Administrateur
// dans les deux cas.
func New(opts Options) (*Sniffer, error) {
	s := &Sniffer{opts: opts, flows: make(map[FlowKey]*FlowStats)}

	if npcapAvailable() {
		eng, err := openNpcap(opts.Iface)
		if err == nil {
			s.npcap = eng
			if opts.PCAPFile != "" {
				w, err := NewPCAPWriter(opts.PCAPFile, DLTEthernet)
				if err != nil {
					eng.Close()
					return nil, err
				}
				s.pcap = w
			}
			return s, nil
		}
		// Npcap présent mais ouverture échouée (droits, périphérique introuvable...) :
		// on retombe sur le raw socket plutôt que d'échouer complètement.
	}

	if err := s.openRawSocket(); err != nil {
		return nil, err
	}
	if opts.PCAPFile != "" {
		w, err := NewPCAPWriter(opts.PCAPFile, DLTRaw)
		if err != nil {
			syscall.Closesocket(s.fd)
			return nil, err
		}
		s.pcap = w
	}
	return s, nil
}

// openRawSocket initialise le mode de repli SIO_RCVALL (IPv4 uniquement).
func (s *Sniffer) openRawSocket() error {
	localIP, err := resolveLocalIPv4(s.opts.Iface)
	if err != nil {
		return fmt.Errorf("résolution de l'adresse locale échouée: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP)
	if err != nil {
		return fmt.Errorf("ouverture raw socket échouée (%s): %w", privilegeHint(), err)
	}

	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], localIP.To4())
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Closesocket(fd)
		return fmt.Errorf("bind sur %s échoué: %w", localIP, err)
	}

	inbuf := rcvallOn
	var outLen uint32
	if err := syscall.WSAIoctl(fd, sioRCVALL, (*byte)(unsafe.Pointer(&inbuf)), 4, nil, 0, &outLen, nil, 0); err != nil {
		syscall.Closesocket(fd)
		return fmt.Errorf("activation SIO_RCVALL échouée (%s): %w", privilegeHint(), err)
	}

	timeoutMs := int32(1000)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soRcvTimeoWindows, int(timeoutMs))

	s.fd = fd
	return nil
}

// resolveLocalIPv4 détermine l'adresse IPv4 locale à laquelle lier le raw
// socket : celle de l'interface demandée, ou à défaut la première adresse
// IPv4 non-loopback trouvée sur la machine.
func resolveLocalIPv4(iface string) (net.IP, error) {
	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("interface %q introuvable: %w", iface, err)
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if v4 := ipnet.IP.To4(); v4 != nil {
					return v4, nil
				}
			}
		}
		return nil, fmt.Errorf("aucune adresse IPv4 sur l'interface %q", iface)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if v4 := ipnet.IP.To4(); v4 != nil {
					return v4, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("aucune interface IPv4 active trouvée (préciser -i)")
}

// Close libère le moteur de capture actif et referme le fichier pcap éventuel.
func (s *Sniffer) Close() error {
	if s.pcap != nil {
		s.pcap.Close()
	}
	if s.npcap != nil {
		s.npcap.Close()
		return nil
	}
	return syscall.Closesocket(s.fd)
}

// Stats retourne une copie des compteurs actuels.
func (s *Sniffer) Stats() Stats {
	return s.stats
}

// UsingNpcap indique si la capture Ethernet complète (Npcap) est active,
// par opposition au repli SIO_RCVALL (IPv4 uniquement).
func (s *Sniffer) UsingNpcap() bool {
	return s.npcap != nil
}

// Run démarre la boucle de capture, quel que soit le moteur actif.
func (s *Sniffer) Run() error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	var deadline time.Time
	if s.opts.Duration > 0 {
		deadline = time.Now().Add(s.opts.Duration)
	}

	go func() {
		<-sigCh
		atomic.StoreInt32(&s.stopped, 1)
	}()

	if s.npcap != nil {
		if err := s.runNpcap(deadline); err != nil {
			return err
		}
	} else {
		if err := s.runRawSocket(deadline); err != nil {
			return err
		}
	}

	if s.opts.AggregateFlows {
		printFlows(s.flows)
	}
	return nil
}

func (s *Sniffer) runNpcap(deadline time.Time) error {
	for atomic.LoadInt32(&s.stopped) == 0 {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil
		}
		if s.opts.MaxPackets > 0 && int(s.stats.Total) >= s.opts.MaxPackets {
			return nil
		}

		data, err := s.npcap.ReadPacket()
		if err != nil {
			if errors.Is(err, errTimeout) {
				continue
			}
			return fmt.Errorf("erreur de lecture Npcap: %w", err)
		}

		pkt := decodeEthernet(data)
		if pkt == nil {
			continue
		}
		s.stats.update(pkt, len(data))
		if !s.opts.Filter.matches(pkt) {
			continue
		}
		if s.pcap != nil {
			s.pcap.WritePacket(data)
		}
		if s.opts.AggregateFlows {
			updateFlow(s.flows, pkt, len(data))
		} else {
			printPacket(s.stats.Total, pkt, s.opts.Verbose)
		}
	}
	return nil
}

func (s *Sniffer) runRawSocket(deadline time.Time) error {
	buf := make([]byte, 65536)

	for atomic.LoadInt32(&s.stopped) == 0 {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil
		}
		if s.opts.MaxPackets > 0 && int(s.stats.Total) >= s.opts.MaxPackets {
			return nil
		}

		n, _, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.ETIMEDOUT {
				continue
			}
			return fmt.Errorf("erreur de lecture socket: %w", err)
		}
		if n == 0 {
			continue
		}

		pkt := decodeIPPacket(buf[:n])
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
	return nil
}
