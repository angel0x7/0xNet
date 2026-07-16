//go:build linux

package sysinfo

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
)

// collectPlatform (Linux) lit /proc/net/route, /etc/resolv.conf et
// /proc/net/arp — aucune dépendance externe, aucun droit particulier requis.
func collectPlatform() (routes []RouteEntry, defaultGW string, dns []string, arp []ARPEntry, err error) {
	routes, defaultGW, err = collectRoutesLinux()
	if err != nil {
		return nil, "", nil, nil, err
	}
	dns = collectDNSLinux()
	arp, _ = collectARPLinux()
	return routes, defaultGW, dns, arp, nil
}

// collectRoutesLinux parse /proc/net/route. Destination/Gateway/Genmask
// sont stockés en little-endian hex dans ce fichier.
func collectRoutesLinux() ([]RouteEntry, string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	var routes []RouteEntry
	defaultGW := ""

	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // en-tête
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		iface := fields[0]
		dest := hexToIPv4(fields[1])
		gw := hexToIPv4(fields[2])
		flagsRaw, _ := strconv.ParseInt(fields[3], 16, 32)
		metric, _ := strconv.Atoi(fields[6])
		mask := hexToIPv4(fields[7])

		entry := RouteEntry{
			Iface:       iface,
			Destination: dest,
			Gateway:     gw,
			Genmask:     mask,
			Metric:      metric,
			Flags:       routeFlagsString(flagsRaw),
			Default:     dest == "0.0.0.0",
		}
		routes = append(routes, entry)
		if entry.Default && gw != "0.0.0.0" {
			defaultGW = gw
		}
	}
	return routes, defaultGW, scanner.Err()
}

// hexToIPv4 convertit une adresse hex little-endian (format /proc/net/route)
// en notation décimale pointée.
func hexToIPv4(hexStr string) string {
	v, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return "0.0.0.0"
	}
	b := make([]byte, 4)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return net.IP(b).String()
}

func routeFlagsString(flags int64) string {
	var parts []string
	if flags&0x0001 != 0 {
		parts = append(parts, "UP")
	}
	if flags&0x0002 != 0 {
		parts = append(parts, "GATEWAY")
	}
	if flags&0x0004 != 0 {
		parts = append(parts, "HOST")
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "|")
}

// collectDNSLinux parse /etc/resolv.conf.
func collectDNSLinux() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				servers = append(servers, fields[1])
			}
		}
	}
	return servers
}

// collectARPLinux parse /proc/net/arp.
func collectARPLinux() ([]ARPEntry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []ARPEntry
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		entries = append(entries, ARPEntry{
			IP:    fields[0],
			Flags: fields[2],
			MAC:   fields[3],
			Iface: fields[5],
		})
	}
	return entries, scanner.Err()
}
