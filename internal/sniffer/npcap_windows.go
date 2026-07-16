//go:build windows

// Intégration optionnelle Npcap (wpcap.dll) : si Npcap est installé sur la
// machine Windows, on l'utilise pour retrouver une capture Ethernet complète
// (trames L2, ARP inclus) au lieu de la limitation IPv4-only du raw socket
// SIO_RCVALL. Chargement dynamique de la DLL via syscall.NewLazyDLL — reste
// donc sans dépendance de build (aucun cgo, aucun module tiers) : si Npcap
// n'est pas installé, le chargement échoue proprement et on retombe sur
// SIO_RCVALL automatiquement.
package sniffer

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	wpcapDLL = syscall.NewLazyDLL("wpcap.dll")

	procFindAllDevs = wpcapDLL.NewProc("pcap_findalldevs")
	procFreeAllDevs = wpcapDLL.NewProc("pcap_freealldevs")
	procOpenLive    = wpcapDLL.NewProc("pcap_open_live")
	procNextEx      = wpcapDLL.NewProc("pcap_next_ex")
	procClose       = wpcapDLL.NewProc("pcap_close")
	procGetErr      = wpcapDLL.NewProc("pcap_geterr")
)

// npcapEngine encapsule une capture via wpcap.dll (Npcap en mode WinPcap
// API-compatible). Fournit des trames Ethernet complètes, contrairement au
// raw socket SIO_RCVALL.
type npcapEngine struct {
	handle uintptr
}

// npcapAvailable teste si wpcap.dll est chargeable sur cette machine.
func npcapAvailable() bool {
	return wpcapDLL.Load() == nil
}

// openNpcap ouvre le périphérique Npcap correspondant à l'interface
// demandée (correspondance par nom/description, sensible à la casse
// ignorée) ou, à défaut, le premier périphérique non-loopback disponible.
func openNpcap(wantedIface string) (*npcapEngine, error) {
	if err := wpcapDLL.Load(); err != nil {
		return nil, fmt.Errorf("wpcap.dll introuvable (Npcap non installé): %w", err)
	}

	device, err := findNpcapDevice(wantedIface)
	if err != nil {
		return nil, err
	}

	deviceC, err := syscall.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}
	errbuf := make([]byte, 256)

	// pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf)
	ret, _, _ := procOpenLive.Call(
		uintptr(unsafe.Pointer(deviceC)),
		uintptr(65536), // snaplen
		uintptr(1),     // promiscuous
		uintptr(1000),  // timeout ms
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if ret == 0 {
		return nil, fmt.Errorf("pcap_open_live échoué sur %q: %s", device, cString(errbuf))
	}

	return &npcapEngine{handle: ret}, nil
}

// ListNpcapDevices énumère les périphériques de capture Npcap disponibles
// (nom interne + description lisible), pour aider à choisir la bonne
// interface avec -i quand plusieurs adaptateurs sont présents.
func ListNpcapDevices() ([]NpcapDevice, error) {
	if err := wpcapDLL.Load(); err != nil {
		return nil, fmt.Errorf("wpcap.dll introuvable (Npcap non installé): %w", err)
	}

	var head uintptr
	errbuf := make([]byte, 256)
	ret, _, _ := procFindAllDevs.Call(
		uintptr(unsafe.Pointer(&head)),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if ret != 0 {
		return nil, fmt.Errorf("pcap_findalldevs échoué: %s", cString(errbuf))
	}
	defer procFreeAllDevs.Call(head)

	type pcapIfRaw struct {
		next        uintptr
		name        uintptr
		description uintptr
		addresses   uintptr
		flags       uint32
	}

	var devices []NpcapDevice
	for p := head; p != 0; {
		raw := (*pcapIfRaw)(unsafe.Pointer(p))
		devices = append(devices, NpcapDevice{
			Name:        cStringAt(raw.name),
			Description: cStringAt(raw.description),
		})
		p = raw.next
	}
	return devices, nil
}

// NpcapDevice décrit un périphérique de capture tel que retourné par
// pcap_findalldevs.
type NpcapDevice struct {
	Name        string
	Description string
}

// findNpcapDevice énumère les périphériques Npcap via pcap_findalldevs et
// sélectionne celui correspondant à wantedIface (sous-chaîne, insensible à
// la casse, testée sur le nom et la description), ou le premier disponible.
func findNpcapDevice(wantedIface string) (string, error) {
	var head uintptr
	errbuf := make([]byte, 256)

	ret, _, _ := procFindAllDevs.Call(
		uintptr(unsafe.Pointer(&head)),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if ret != 0 {
		return "", fmt.Errorf("pcap_findalldevs échoué: %s", cString(errbuf))
	}
	defer procFreeAllDevs.Call(head)

	if head == 0 {
		return "", fmt.Errorf("aucun périphérique de capture Npcap trouvé")
	}

	type pcapIfRaw struct {
		next        uintptr
		name        uintptr
		description uintptr
		addresses   uintptr
		flags       uint32
	}

	var fallback string
	wanted := strings.ToLower(wantedIface)

	for p := head; p != 0; {
		raw := (*pcapIfRaw)(unsafe.Pointer(p))
		name := cStringAt(raw.name)
		desc := cStringAt(raw.description)

		if fallback == "" {
			fallback = name
		}
		if wanted != "" && (strings.Contains(strings.ToLower(name), wanted) || strings.Contains(strings.ToLower(desc), wanted)) {
			return name, nil
		}
		p = raw.next
	}

	if wanted != "" {
		return "", fmt.Errorf("aucun périphérique Npcap ne correspond à %q", wantedIface)
	}
	if fallback == "" {
		return "", fmt.Errorf("aucun périphérique de capture disponible")
	}
	return fallback, nil
}

// ReadPacket lit le prochain paquet (trame Ethernet complète) via
// pcap_next_ex, avec re-tentative sur timeout interne à Npcap (code 0).
func (e *npcapEngine) ReadPacket() ([]byte, error) {
	var pktHeader, pktData uintptr

	for {
		// int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **h, const u_char **data)
		ret, _, _ := procNextEx.Call(e.handle, uintptr(unsafe.Pointer(&pktHeader)), uintptr(unsafe.Pointer(&pktData)))
		switch int32(ret) {
		case 1:
			// struct pcap_pkthdr { struct timeval ts (8 octets sur Windows) ; bpf_u_int32 caplen ; bpf_u_int32 len ; }
			caplen := *(*uint32)(unsafe.Pointer(pktHeader + 8))
			if caplen == 0 || caplen > 65536 {
				continue
			}
			data := make([]byte, caplen)
			src := unsafe.Slice((*byte)(unsafe.Pointer(pktData)), caplen)
			copy(data, src)
			return data, nil
		case 0:
			// timeout interne pcap, on retente immédiatement (la boucle appelante gère son propre deadline)
			return nil, errTimeout
		default:
			errbuf, _, _ := procGetErr.Call(e.handle)
			return nil, fmt.Errorf("pcap_next_ex erreur: %s", cStringAt(errbuf))
		}
	}
}

// Close libère la capture Npcap.
func (e *npcapEngine) Close() {
	if e.handle != 0 {
		procClose.Call(e.handle)
	}
}

func cStringAt(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var b []byte
	for i := 0; ; i++ {
		c := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

func cString(buf []byte) string {
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n])
}

var errTimeout = fmt.Errorf("npcap: timeout de lecture")
