package sysinfo

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ToJSON sérialise le snapshot en JSON indenté — pensé pour être collé
// directement dans un ticket ou ingéré par un SIEM.
func (s *SystemSnapshot) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// Save écrit le snapshot au format JSON dans un fichier — sert de
// référence pour un diff ultérieur (`sysinfo -diff`).
func (s *SystemSnapshot) Save(path string) error {
	data, err := s.ToJSON()
	if err != nil {
		return fmt.Errorf("sérialisation JSON échouée: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("écriture %q échouée: %w", path, err)
	}
	return nil
}

// Load relit un snapshot précédemment sauvegardé.
func Load(path string) (*SystemSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lecture %q échouée: %w", path, err)
	}
	var snap SystemSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing JSON %q échoué: %w", path, err)
	}
	return &snap, nil
}

// DiffEntry décrit un changement détecté entre deux snapshots.
type DiffEntry struct {
	Category string `json:"category"` // "interface", "route", "dns", "arp", "gateway"
	Item     string `json:"item"`
	Change   string `json:"change"` // "ajouté", "supprimé", "modifié"
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
}

// Diff compare deux snapshots (before -> after) et retourne la liste des
// changements détectés : idéal pour repérer ce qui a changé entre deux
// diagnostics ("pourquoi ça marchait hier et plus aujourd'hui").
func Diff(before, after *SystemSnapshot) []DiffEntry {
	var diffs []DiffEntry

	// --- Passerelle par défaut ---
	if before.DefaultGW != after.DefaultGW {
		diffs = append(diffs, DiffEntry{"gateway", "default_gateway", "modifié", before.DefaultGW, after.DefaultGW})
	}

	// --- Interfaces : état UP/DOWN et adresses ---
	beforeIf := indexInterfaces(before.Interfaces)
	afterIf := indexInterfaces(after.Interfaces)
	for name, b := range beforeIf {
		a, exists := afterIf[name]
		if !exists {
			diffs = append(diffs, DiffEntry{"interface", name, "supprimée", fmt.Sprintf("UP=%v", b.Up), ""})
			continue
		}
		if b.Up != a.Up {
			diffs = append(diffs, DiffEntry{"interface", name + " (état)", "modifié",
				fmt.Sprintf("UP=%v", b.Up), fmt.Sprintf("UP=%v", a.Up)})
		}
		if !sameStrings(b.Addrs, a.Addrs) {
			diffs = append(diffs, DiffEntry{"interface", name + " (adresses)", "modifié",
				fmt.Sprint(b.Addrs), fmt.Sprint(a.Addrs)})
		}
	}
	for name := range afterIf {
		if _, exists := beforeIf[name]; !exists {
			diffs = append(diffs, DiffEntry{"interface", name, "ajoutée", "", "nouvelle interface"})
		}
	}

	// --- Routes par défaut (par passerelle) ---
	beforeGW := defaultGateways(before.Routes)
	afterGW := defaultGateways(after.Routes)
	for gw := range beforeGW {
		if !afterGW[gw] {
			diffs = append(diffs, DiffEntry{"route", gw, "supprimée", "route par défaut", ""})
		}
	}
	for gw := range afterGW {
		if !beforeGW[gw] {
			diffs = append(diffs, DiffEntry{"route", gw, "ajoutée", "", "nouvelle route par défaut"})
		}
	}

	// --- DNS ---
	if !sameStrings(sortedCopy(before.DNSServers), sortedCopy(after.DNSServers)) {
		diffs = append(diffs, DiffEntry{"dns", "résolveurs", "modifié", fmt.Sprint(before.DNSServers), fmt.Sprint(after.DNSServers)})
	}

	// --- ARP : changements de MAC pour une IP donnée (conflit IP possible) ---
	beforeARP := indexARP(before.ARPTable)
	afterARP := indexARP(after.ARPTable)
	for ip, mac := range beforeARP {
		if newMac, exists := afterARP[ip]; exists && newMac != mac {
			diffs = append(diffs, DiffEntry{"arp", ip, "modifié (conflit IP possible)", mac, newMac})
		}
	}

	return diffs
}

func indexInterfaces(ifs []InterfaceInfo) map[string]InterfaceInfo {
	m := make(map[string]InterfaceInfo, len(ifs))
	for _, i := range ifs {
		m[i.Name] = i
	}
	return m
}

func indexARP(entries []ARPEntry) map[string]string {
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		m[e.IP] = e.MAC
	}
	return m
}

func defaultGateways(routes []RouteEntry) map[string]bool {
	m := make(map[string]bool)
	for _, r := range routes {
		if r.Default && r.Gateway != "" && r.Gateway != "0.0.0.0" {
			m[r.Gateway] = true
		}
	}
	return m
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := sortedCopy(a), sortedCopy(b)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

func sortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

// PrintDiff affiche les changements détectés dans un format lisible.
func PrintDiff(diffs []DiffEntry) {
	if len(diffs) == 0 {
		fmt.Println("Aucun changement détecté entre les deux snapshots.")
		return
	}
	fmt.Printf("=== %d changement(s) détecté(s) ===\n\n", len(diffs))
	for _, d := range diffs {
		fmt.Printf("[%s] %s : %s\n", d.Category, d.Item, d.Change)
		if d.Before != "" || d.After != "" {
			fmt.Printf("    avant: %s\n    après: %s\n", d.Before, d.After)
		}
	}
}
