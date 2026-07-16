//go:build windows

package sysinfo

import (
	"bufio"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// collectPlatform (Windows) n'a pas d'équivalent direct de /proc/net/* :
// on s'appuie sur les commandes système standard (présentes sur tout
// Windows), sans dépendance externe. C'est moins élégant qu'un appel direct
// à l'API IP Helper (GetIpForwardTable/GetIpNetTable), mais ça fonctionne
// sans droits particuliers et sans module tiers.
func collectPlatform() (routes []RouteEntry, defaultGW string, dns []string, arp []ARPEntry, err error) {
	routes, defaultGW = collectRoutesWindows()
	dns = collectDNSWindows()
	arp = collectARPWindows()
	return routes, defaultGW, dns, arp, nil
}

// collectRoutesWindows parse la sortie de `route print -4`.
func collectRoutesWindows() ([]RouteEntry, string) {
	out, err := exec.Command("route", "print", "-4").Output()
	if err != nil {
		return nil, ""
	}

	var routes []RouteEntry
	defaultGW := ""

	// Ligne type :
	//           0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
	lineRe := regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s*$`)

	inTable := false
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Active Routes") {
			inTable = true
			continue
		}
		if strings.Contains(line, "Persistent Routes") {
			inTable = false
			continue
		}
		if !inTable {
			continue
		}
		m := lineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		dest, mask, gw, iface := m[1], m[2], m[3], m[4]
		metric, _ := strconv.Atoi(m[5])

		entry := RouteEntry{
			Iface:       iface,
			Destination: dest,
			Gateway:     gw,
			Genmask:     mask,
			Metric:      metric,
			Flags:       "-",
			Default:     dest == "0.0.0.0" && mask == "0.0.0.0",
		}
		routes = append(routes, entry)
		if entry.Default && (defaultGW == "" || entry.Metric < metric) {
			defaultGW = gw
		}
	}
	return routes, defaultGW
}

// collectDNSWindows parse `ipconfig /all` (lignes "DNS Servers" + suites
// indentées).
func collectDNSWindows() []string {
	out, err := exec.Command("ipconfig", "/all").Output()
	if err != nil {
		return nil
	}

	var servers []string
	seen := map[string]bool{}
	ipRe := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)

	inDNSBlock := false
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.Contains(line, "DNS Servers") {
			inDNSBlock = true
			if m := ipRe.FindString(line); m != "" && !seen[m] {
				servers = append(servers, m)
				seen[m] = true
			}
			continue
		}
		if inDNSBlock {
			// une ligne de continuation est indentée et ne contient qu'une IP,
			// sans "label : valeur"
			if strings.Contains(trimmed, ":") {
				inDNSBlock = false
				continue
			}
			if m := ipRe.FindString(trimmed); m != "" && !seen[m] {
				servers = append(servers, m)
				seen[m] = true
				continue
			}
			inDNSBlock = false
		}
	}
	return servers
}

// collectARPWindows parse `arp -a`.
func collectARPWindows() []ARPEntry {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil
	}

	var entries []ARPEntry
	currentIface := ""
	ifaceRe := regexp.MustCompile(`Interface:\s*([\d.]+)`)
	entryRe := regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)`)

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if m := ifaceRe.FindStringSubmatch(line); m != nil {
			currentIface = m[1]
			continue
		}
		if m := entryRe.FindStringSubmatch(line); m != nil {
			entries = append(entries, ARPEntry{
				IP:    m[1],
				MAC:   strings.ReplaceAll(m[2], "-", ":"),
				Iface: currentIface,
				Flags: m[3],
			})
		}
	}
	return entries
}
