// Package sysinfo collecte le contexte réseau d'une machine :
// interfaces, adresses IP, table de routage, résolveurs DNS, table ARP.
// Ces informations servent de socle au pipeline de diagnostic OSI.
//
// La collecte des interfaces (net.Interfaces) est portable Linux/Windows.
// Le reste (routes, DNS, ARP) dépend de l'OS et est implémenté séparément
// dans sysinfo_linux.go (lecture de /proc/net/*) et sysinfo_windows.go
// (parsing des commandes route/arp/ipconfig via l'API Win32 quand possible).
package sysinfo

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// InterfaceInfo décrit une interface réseau et son état L1/L2.
type InterfaceInfo struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MAC       string   `json:"mac"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
	Broadcast bool     `json:"broadcast"`
	Multicast bool     `json:"multicast"`
	Addrs     []string `json:"addrs"` // adresses IPv4/IPv6 (CIDR)
}

// RouteEntry représente une ligne de la table de routage IPv4.
type RouteEntry struct {
	Iface       string `json:"iface"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Genmask     string `json:"genmask"`
	Metric      int    `json:"metric"`
	Flags       string `json:"flags"`
	Default     bool   `json:"default"`
}

// ARPEntry représente une ligne de la table ARP / voisinage.
type ARPEntry struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Iface string `json:"iface"`
	Flags string `json:"flags"`
}

// SystemSnapshot regroupe l'ensemble du contexte réseau collecté.
type SystemSnapshot struct {
	OS         string           `json:"os"`
	Hostname   string           `json:"hostname"`
	Timestamp  time.Time        `json:"timestamp"`
	Interfaces []InterfaceInfo  `json:"interfaces"`
	Routes     []RouteEntry     `json:"routes"`
	DefaultGW  string           `json:"default_gateway"`
	DNSServers []string         `json:"dns_servers"`
	ARPTable   []ARPEntry       `json:"arp_table"`
}

// Collect construit un snapshot complet de la machine, quel que soit l'OS.
func Collect() (*SystemSnapshot, error) {
	snap := &SystemSnapshot{OS: runtime.GOOS, Timestamp: time.Now()}

	if h, err := os.Hostname(); err == nil {
		snap.Hostname = h
	}

	ifaces, err := collectInterfaces()
	if err != nil {
		return nil, fmt.Errorf("collecte interfaces: %w", err)
	}
	snap.Interfaces = ifaces

	// Partie spécifique OS : implémentée dans sysinfo_linux.go / sysinfo_windows.go
	routes, defGW, dns, arp, err := collectPlatform()
	if err != nil {
		// Non bloquant : on retourne quand même les interfaces déjà collectées.
		snap.DNSServers = nil
	} else {
		snap.Routes = routes
		snap.DefaultGW = defGW
		snap.DNSServers = dns
		snap.ARPTable = arp
	}

	return snap, nil
}

// collectInterfaces est portable (package net standard).
func collectInterfaces() ([]InterfaceInfo, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []InterfaceInfo
	for _, i := range ifs {
		info := InterfaceInfo{
			Name:      i.Name,
			Index:     i.Index,
			MAC:       i.HardwareAddr.String(),
			MTU:       i.MTU,
			Up:        i.Flags&net.FlagUp != 0,
			Loopback:  i.Flags&net.FlagLoopback != 0,
			Broadcast: i.Flags&net.FlagBroadcast != 0,
			Multicast: i.Flags&net.FlagMulticast != 0,
		}
		addrs, err := i.Addrs()
		if err == nil {
			for _, a := range addrs {
				info.Addrs = append(info.Addrs, a.String())
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// Print affiche un résumé lisible du snapshot dans le terminal.
func (s *SystemSnapshot) Print() {
	fmt.Printf("=== Contexte système : %s (%s) ===\n\n", s.Hostname, s.OS)

	fmt.Println("--- Interfaces (L1/L2) ---")
	for _, i := range s.Interfaces {
		state := "DOWN"
		if i.Up {
			state = "UP"
		}
		fmt.Printf("  %-16s [%s] MAC=%-17s MTU=%-5d addrs=%s\n",
			i.Name, state, orDash(i.MAC), i.MTU, strings.Join(i.Addrs, ", "))
	}

	fmt.Println("\n--- Routage (L3) ---")
	if len(s.Routes) == 0 {
		fmt.Println("  (non disponible)")
	}
	for _, r := range s.Routes {
		tag := ""
		if r.Default {
			tag = " (default)"
		}
		fmt.Printf("  %-16s dest=%-16s gw=%-16s mask=%-16s metric=%-4d flags=%s%s\n",
			r.Iface, r.Destination, r.Gateway, r.Genmask, r.Metric, r.Flags, tag)
	}
	fmt.Printf("  Passerelle par défaut : %s\n", orDash(s.DefaultGW))

	fmt.Println("\n--- DNS ---")
	if len(s.DNSServers) == 0 {
		fmt.Println("  Aucun résolveur trouvé")
	}
	for _, d := range s.DNSServers {
		fmt.Printf("  nameserver %s\n", d)
	}

	fmt.Println("\n--- Table ARP / voisinage ---")
	if len(s.ARPTable) == 0 {
		fmt.Println("  (vide ou non disponible)")
	}
	for _, a := range s.ARPTable {
		fmt.Printf("  %-16s -> %-17s dev %-16s flags=%s\n", a.IP, a.MAC, a.Iface, a.Flags)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
