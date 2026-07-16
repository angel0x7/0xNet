// Package diagnostics implémente le pipeline de diagnostic "premier niveau"
// qui parcourt le modèle OSI couche par couche (L1/L2 -> L7) et rend un
// verdict exploitable par un professionnel réseau : OK / WARNING / FAIL,
// avec l'explication et la couche fautive.
package diagnostics

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"0xnetadmin/internal/nettools"
	"0xnetadmin/internal/sysinfo"
)

// Status représente le verdict d'un test.
type Status string

const (
	StatusOK      Status = "OK"
	StatusWarning Status = "WARNING"
	StatusFail    Status = "FAIL"
	StatusSkip    Status = "SKIP"
)

// Result est le résultat d'un test de diagnostic pour une couche donnée.
type Result struct {
	Layer   string        `json:"layer"` // ex: "L1/L2", "L3", "L4", "L7"
	Test    string        `json:"test"`
	Status  Status        `json:"status"`
	Detail  string        `json:"detail"`
	Elapsed time.Duration `json:"elapsed_ns"`
}

// Report est le rapport complet du pipeline, dans l'ordre d'exécution.
type Report struct {
	Results   []Result `json:"results"`
	StoppedAt string   `json:"stopped_at,omitempty"` // couche où le pipeline s'est arrêté, si échec bloquant
}

// ToJSON sérialise le rapport en JSON indenté — pour intégration
// dans un ticket ou ingestion par un SIEM.
func (r *Report) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Options configure le pipeline de diagnostic.
type Options struct {
	Iface       string        // interface à tester en priorité ("" = auto)
	TargetHost  string        // hôte HTTP(S)/DNS à tester en L7, défaut www.google.com
	DNSName     string        // nom à résoudre en L7, défaut le même que TargetHost
	Ports       []int         // ports TCP à tester en L4, défaut [443, 80]
	PingTimeout time.Duration // défaut 2s
	StopOnFail  bool          // arrêter le pipeline dès le premier FAIL bloquant
}

func defaultOptions(o Options) Options {
	if o.TargetHost == "" {
		o.TargetHost = "www.google.com"
	}
	if o.DNSName == "" {
		o.DNSName = o.TargetHost
	}
	if o.PingTimeout == 0 {
		o.PingTimeout = 2 * time.Second
	}
	if len(o.Ports) == 0 {
		o.Ports = []int{443, 80}
	}
	return o
}

// Run exécute le pipeline complet et retourne le rapport.
func Run(opts Options) *Report {
	opts = defaultOptions(opts)
	report := &Report{}

	snap, err := sysinfo.Collect()
	if err != nil {
		report.add(Result{"L1/L2", "Collecte système", StatusFail, err.Error(), 0})
		report.StoppedAt = "L1/L2"
		return report
	}

	// --- L1/L2 : interface physique ---
	iface, res := checkInterface(snap, opts.Iface)
	report.add(res)
	if res.Status == StatusFail && opts.StopOnFail {
		report.StoppedAt = "L1/L2"
		return report
	}

	// --- L1/L2 : compteurs d'erreurs de l'interface (Linux uniquement) ---
	report.add(checkInterfaceCounters(iface))

	// --- L2 : ARP / résolution de la passerelle ---
	report.add(checkGatewayARP(snap))

	// --- L3 : IP configurée + passerelle joignable ---
	res = checkIPConfig(snap)
	report.add(res)
	if res.Status == StatusFail && opts.StopOnFail {
		report.StoppedAt = "L3"
		return report
	}

	// --- L3 : passerelles multiples / routage asymétrique potentiel ---
	report.add(checkMultipleGateways(snap))

	res = checkGatewayReachable(snap, opts.PingTimeout)
	report.add(res)
	if res.Status == StatusFail && opts.StopOnFail {
		report.StoppedAt = "L3"
		return report
	}

	// --- L3 : Path MTU Discovery vers la cible ---
	report.add(checkPathMTU(opts.TargetHost))

	// --- L4 : test de connexion TCP multi-ports avec classification firewall ---
	l4Results := checkTCPPorts(opts.TargetHost, opts.Ports, 3*time.Second)
	for _, r := range l4Results {
		report.add(r)
	}
	if opts.StopOnFail && allFailed(l4Results) {
		report.StoppedAt = "L4"
		return report
	}

	// --- L7 : DNS (résolveur système) ---
	res, ips := checkDNS(snap, opts.DNSName, 3*time.Second)
	report.add(res)
	if res.Status == StatusFail && opts.StopOnFail {
		report.StoppedAt = "L7 (DNS)"
		return report
	}
	_ = ips

	// --- L7 : cohérence multi-résolveur (détection hijacking/pollution DNS) ---
	report.add(checkDNSConsistency(opts.DNSName, snap.DNSServers, 3*time.Second))

	// --- L7 : HTTP(S) + certificat TLS + horloge système ---
	httpRes, respDate := checkHTTPS(opts.TargetHost, 5*time.Second)
	report.add(httpRes)
	if respDate != nil {
		report.add(checkClockSkew(*respDate))
	}

	return report
}

func (r *Report) add(res Result) {
	r.Results = append(r.Results, res)
}

func allFailed(results []Result) bool {
	for _, r := range results {
		if r.Status != StatusFail {
			return false
		}
	}
	return len(results) > 0
}

// ---- Tests individuels ----

func checkInterface(snap *sysinfo.SystemSnapshot, wanted string) (string, Result) {
	start := time.Now()
	var candidate *sysinfo.InterfaceInfo
	for i := range snap.Interfaces {
		ifc := snap.Interfaces[i]
		if ifc.Loopback {
			continue
		}
		if wanted != "" && ifc.Name != wanted {
			continue
		}
		if len(ifc.Addrs) > 0 {
			candidate = &snap.Interfaces[i]
			break
		}
		if candidate == nil {
			candidate = &snap.Interfaces[i]
		}
	}

	if candidate == nil {
		return "", Result{"L1/L2", "Interface réseau active", StatusFail,
			"Aucune interface non-loopback détectée sur la machine.", time.Since(start)}
	}
	if !candidate.Up {
		return candidate.Name, Result{"L1/L2", "Interface réseau active", StatusFail,
			fmt.Sprintf("Interface %s détectée mais DOWN (câble débranché, driver, ou admin down).", candidate.Name),
			time.Since(start)}
	}
	if len(candidate.Addrs) == 0 {
		return candidate.Name, Result{"L1/L2", "Interface réseau active", StatusWarning,
			fmt.Sprintf("Interface %s UP mais sans adresse IP (DHCP en échec ou config manquante).", candidate.Name),
			time.Since(start)}
	}
	return candidate.Name, Result{"L1/L2", "Interface réseau active", StatusOK,
		fmt.Sprintf("%s UP, MTU=%d, adresses=%s", candidate.Name, candidate.MTU, strings.Join(candidate.Addrs, ", ")),
		time.Since(start)}
}

// checkInterfaceCounters lit les compteurs d'erreurs bas niveau exposés par
// le noyau Linux (/sys/class/net/<if>/statistics). Sous Windows, ces
// compteurs ne sont pas exposés simplement sans WMI/PowerShell — le test est
// marqué SKIP plutôt que de donner un faux résultat.
func checkInterfaceCounters(iface string) Result {
	start := time.Now()
	if iface == "" {
		return Result{"L1/L2", "Compteurs d'erreurs interface", StatusSkip, "Pas d'interface identifiée.", time.Since(start)}
	}

	if runtime.GOOS == "windows" {
		return checkInterfaceCountersWindows(iface, start)
	}
	if runtime.GOOS != "linux" {
		return Result{"L1/L2", "Compteurs d'erreurs interface", StatusSkip,
			"Non disponible sur " + runtime.GOOS + ".", time.Since(start)}
	}

	base := filepath.Join("/sys/class/net", iface, "statistics")
	read := func(name string) int64 {
		b, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			return -1
		}
		v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		return v
	}

	rxErrors := read("rx_errors")
	txErrors := read("tx_errors")
	rxDropped := read("rx_dropped")
	txDropped := read("tx_dropped")
	collisions := read("collisions")

	if rxErrors < 0 {
		return Result{"L1/L2", "Compteurs d'erreurs interface", StatusSkip,
			fmt.Sprintf("Statistiques indisponibles pour %s.", iface), time.Since(start)}
	}

	detail := fmt.Sprintf("%s: rx_errors=%d tx_errors=%d rx_dropped=%d tx_dropped=%d collisions=%d",
		iface, rxErrors, txErrors, rxDropped, txDropped, collisions)

	if rxErrors > 0 || txErrors > 0 || collisions > 0 {
		return Result{"L1/L2", "Compteurs d'erreurs interface", StatusWarning,
			detail + " — erreurs physiques détectées (câble, duplex mismatch, NIC défaillante).", time.Since(start)}
	}
	if rxDropped > 0 || txDropped > 0 {
		return Result{"L1/L2", "Compteurs d'erreurs interface", StatusWarning,
			detail + " — paquets droppés (buffer saturé, ACL locale, charge CPU).", time.Since(start)}
	}
	return Result{"L1/L2", "Compteurs d'erreurs interface", StatusOK, detail, time.Since(start)}
}

// windowsAdapterStats reflète le sous-ensemble utile de la sortie JSON de
// Get-NetAdapterStatistics (PowerShell).
type windowsAdapterStats struct {
	ReceivedPacketErrors  int64 `json:"ReceivedPacketErrors"`
	OutboundPacketErrors  int64 `json:"OutboundPacketErrors"`
	ReceivedDiscardedPackets int64 `json:"ReceivedDiscardedPackets"`
}

// checkInterfaceCountersWindows interroge Get-NetAdapterStatistics en
// PowerShell (présent sur tout Windows 8+/Server 2012+, aucune dépendance
// externe) et parse sa sortie JSON.
func checkInterfaceCountersWindows(iface string, start time.Time) Result {
	psCmd := fmt.Sprintf(
		"Get-NetAdapterStatistics -Name '%s' | Select-Object ReceivedPacketErrors,OutboundPacketErrors,ReceivedDiscardedPackets | ConvertTo-Json",
		strings.ReplaceAll(iface, "'", "''"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).Output()
	if err != nil {
		return Result{"L1/L2", "Compteurs d'erreurs interface", StatusSkip,
			fmt.Sprintf("Get-NetAdapterStatistics indisponible pour %q (%v).", iface, err), time.Since(start)}
	}

	var stats windowsAdapterStats
	if err := json.Unmarshal(out, &stats); err != nil {
		return Result{"L1/L2", "Compteurs d'erreurs interface", StatusSkip,
			"Réponse PowerShell illisible.", time.Since(start)}
	}

	detail := fmt.Sprintf("%s: ReceivedPacketErrors=%d OutboundPacketErrors=%d ReceivedDiscardedPackets=%d",
		iface, stats.ReceivedPacketErrors, stats.OutboundPacketErrors, stats.ReceivedDiscardedPackets)

	if stats.ReceivedPacketErrors > 0 || stats.OutboundPacketErrors > 0 {
		return Result{"L1/L2", "Compteurs d'erreurs interface", StatusWarning,
			detail + " — erreurs physiques détectées (câble, duplex mismatch, NIC défaillante).", time.Since(start)}
	}
	if stats.ReceivedDiscardedPackets > 0 {
		return Result{"L1/L2", "Compteurs d'erreurs interface", StatusWarning,
			detail + " — paquets rejetés (buffer saturé, charge CPU).", time.Since(start)}
	}
	return Result{"L1/L2", "Compteurs d'erreurs interface", StatusOK, detail, time.Since(start)}
}

func checkGatewayARP(snap *sysinfo.SystemSnapshot) Result {
	start := time.Now()
	if snap.DefaultGW == "" {
		return Result{"L2", "Résolution ARP passerelle", StatusSkip, "Pas de passerelle par défaut connue.", time.Since(start)}
	}
	for _, a := range snap.ARPTable {
		if a.IP == snap.DefaultGW && a.MAC != "00:00:00:00:00:00" {
			return Result{"L2", "Résolution ARP passerelle", StatusOK,
				fmt.Sprintf("%s résolue en %s", snap.DefaultGW, a.MAC), time.Since(start)}
		}
	}
	return Result{"L2", "Résolution ARP passerelle", StatusWarning,
		fmt.Sprintf("Aucune entrée ARP pour la passerelle %s (pas encore résolue, ou hors sous-réseau L2).", snap.DefaultGW),
		time.Since(start)}
}

func checkIPConfig(snap *sysinfo.SystemSnapshot) Result {
	start := time.Now()
	if snap.DefaultGW == "" {
		return Result{"L3", "Route par défaut", StatusFail,
			"Aucune route par défaut dans la table de routage : pas de sortie WAN possible.", time.Since(start)}
	}
	return Result{"L3", "Route par défaut", StatusOK,
		fmt.Sprintf("Passerelle par défaut : %s", snap.DefaultGW), time.Since(start)}
}

// checkMultipleGateways détecte la présence de plusieurs routes par défaut
// (sur des interfaces différentes) : source classique de routage
// asymétrique, de perte intermittente, ou de conflit VPN/split-tunneling.
func checkMultipleGateways(snap *sysinfo.SystemSnapshot) Result {
	start := time.Now()
	seen := map[string]string{} // gateway -> iface
	var gateways []string
	for _, r := range snap.Routes {
		if r.Default && r.Gateway != "" && r.Gateway != "0.0.0.0" {
			if _, ok := seen[r.Gateway]; !ok {
				seen[r.Gateway] = r.Iface
				gateways = append(gateways, r.Gateway)
			}
		}
	}
	if len(gateways) <= 1 {
		return Result{"L3", "Passerelles par défaut multiples", StatusOK,
			"Une seule route par défaut active.", time.Since(start)}
	}
	sort.Strings(gateways)
	var parts []string
	for _, gw := range gateways {
		parts = append(parts, fmt.Sprintf("%s via %s", gw, seen[gw]))
	}
	return Result{"L3", "Passerelles par défaut multiples", StatusWarning,
		fmt.Sprintf("%d routes par défaut détectées (%s) : risque de routage asymétrique ou conflit VPN/split-tunnel.",
			len(gateways), strings.Join(parts, ", ")), time.Since(start)}
}

func checkGatewayReachable(snap *sysinfo.SystemSnapshot, timeout time.Duration) Result {
	start := time.Now()
	if snap.DefaultGW == "" {
		return Result{"L3", "Ping passerelle", StatusSkip, "Pas de passerelle à tester.", time.Since(start)}
	}

	// Ping ICMP natif en priorité (aucune dépendance au binaire système) ;
	// repli sur `ping` système si le raw socket ICMP n'est pas accessible
	// (droits insuffisants) pour ne pas dégrader l'expérience non-root/non-admin.
	if res, err := nettools.Ping(snap.DefaultGW, timeout); err == nil {
		elapsed := time.Since(start)
		return Result{"L3", "Ping passerelle", StatusOK,
			fmt.Sprintf("%s a répondu en %s (ping ICMP natif)", res.From, res.RTT.Round(time.Microsecond)), elapsed}
	}

	ok, detail := pingHost(snap.DefaultGW, timeout)
	elapsed := time.Since(start)
	if ok {
		return Result{"L3", "Ping passerelle", StatusOK, detail + " (via binaire système)", elapsed}
	}
	return Result{"L3", "Ping passerelle", StatusFail,
		fmt.Sprintf("Passerelle %s injoignable (%s) : problème L3 probable (câblage, ARP, ACL, panne équipement).",
			snap.DefaultGW, detail), elapsed}
}

// checkPathMTU teste plusieurs tailles de paquet avec le bit "Don't
// Fragment" pour détecter un problème de MTU sur le chemin (tunnel VPN,
// SD-WAN, PPPoE...). Symptôme classique : ping simple OK, mais gros
// transferts (HTTPS, RDP, SMB) qui se bloquent ou rament.
func checkPathMTU(host string) Result {
	start := time.Now()

	// Recherche dichotomique de la plus grande taille de payload ICMP
	// passant sans fragmentation (bit DF), entre 1200 et 1472 octets
	// (1472 = 1500 - 20 IP - 8 ICMP, la MTU Ethernet standard).
	const (
		lowBound  = 1200 // borne basse quasi toujours acceptée
		highBound = 1472 // MTU Ethernet standard (1500) moins les en-têtes IP+ICMP
	)

	if !pingDF(host, lowBound, 1*time.Second) {
		return Result{"L3", "Path MTU Discovery", StatusSkip,
			fmt.Sprintf("Impossible de conclure vers %s (ICMP peut-être filtré, ou MTU < %d — non bloquant).", host, lowBound),
			time.Since(start)}
	}
	if pingDF(host, highBound, 1*time.Second) {
		return Result{"L3", "Path MTU Discovery", StatusOK,
			fmt.Sprintf("MTU pleine taille (1500) supportée vers %s.", host), time.Since(start)}
	}

	// dichotomie entre lowBound (OK) et highBound (KO)
	lo, hi := lowBound, highBound
	for hi-lo > 8 { // résolution à 8 octets près, suffisant pour un diagnostic
		mid := (lo + hi) / 2
		if pingDF(host, mid, 1*time.Second) {
			lo = mid
		} else {
			hi = mid
		}
	}

	return Result{"L3", "Path MTU Discovery", StatusWarning,
		fmt.Sprintf("MTU effective limitée à ~%d octets vers %s (au lieu de 1500) : tunnel/VPN/PPPoE sur le chemin, "+
			"vérifier la config MSS clamping / MTU des interfaces intermédiaires.", lo+28, host), time.Since(start)}
}

// pingDF envoie un seul ping avec le bit DF positionné et une taille de
// payload donnée ; retourne true si la taille passe sans fragmentation.
func pingDF(host string, payloadSize int, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-f", "-l", strconv.Itoa(payloadSize),
			"-n", "1", "-w", strconv.FormatInt(timeout.Milliseconds(), 10), host)
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-D", "-s", strconv.Itoa(payloadSize),
			"-c", "1", "-W", strconv.FormatInt(timeout.Milliseconds(), 10), host)
	default: // linux
		cmd = exec.CommandContext(ctx, "ping", "-M", "do", "-s", strconv.Itoa(payloadSize),
			"-c", "1", "-W", strconv.Itoa(int(timeout.Seconds())), host)
	}
	return cmd.Run() == nil
}

// pingHost utilise la commande système `ping` pour un test rapide de
// joignabilité. La syntaxe diffère entre Linux/macOS et Windows.
func pingHost(host string, timeout time.Duration) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.FormatInt(timeout.Milliseconds(), 10), host)
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.FormatInt(timeout.Milliseconds(), 10), host)
	default: // linux et autres unix
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(int(timeout.Seconds())), host)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("timeout/erreur (%v)", err)
	}
	return true, strings.TrimSpace(lastLine(string(out)))
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		return s
	}
	return lines[len(lines)-1]
}

// checkTCPPorts teste chaque port et classe précisément la cause d'échec :
// OPEN (handshake réussi), REFUSED (RST reçu — hôte vivant, port fermé,
// donc pas un problème réseau), ou FILTERED (timeout — firewall/ACL qui
// droppe silencieusement, le cas le plus fréquent en entreprise).
func checkTCPPorts(host string, ports []int, timeout time.Duration) []Result {
	var results []Result
	for _, port := range ports {
		start := time.Now()
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		elapsed := time.Since(start)

		testName := fmt.Sprintf("Connexion TCP :%d", port)

		if err == nil {
			conn.Close()
			results = append(results, Result{"L4", testName, StatusOK,
				fmt.Sprintf("Handshake réussi vers %s en %s (port OUVERT).", addr, elapsed), elapsed})
			continue
		}

		switch classifyTCPError(err) {
		case "refused":
			results = append(results, Result{"L4", testName, StatusWarning,
				fmt.Sprintf("%s : connexion REFUSÉE (RST reçu) — hôte joignable mais rien n'écoute sur ce port, ce n'est pas un problème réseau.", addr), elapsed})
		default:
			results = append(results, Result{"L4", testName, StatusFail,
				fmt.Sprintf("%s : TIMEOUT après %s — port probablement FILTRÉ par un firewall/ACL (drop silencieux).", addr, elapsed), elapsed})
		}
	}
	return results
}

// classifyTCPError distingue un rejet explicite (RST -> "connection
// refused") d'un timeout de connexion (filtrage silencieux).
func classifyTCPError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "refused") {
		return "refused"
	}
	return "filtered"
}

func checkDNS(snap *sysinfo.SystemSnapshot, name string, timeout time.Duration) (Result, []string) {
	start := time.Now()
	if len(snap.DNSServers) == 0 {
		return Result{"L7", "Résolution DNS (résolveur système)", StatusWarning,
			"Aucun résolveur DNS configuré.", time.Since(start)}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resolver := net.DefaultResolver
	addrs, err := resolver.LookupHost(ctx, name)
	elapsed := time.Since(start)
	if err != nil {
		return Result{"L7", "Résolution DNS (résolveur système)", StatusFail,
			fmt.Sprintf("Résolution de %s échouée (%v) via %s : problème DNS (résolveur injoignable, ou nom invalide).",
				name, err, strings.Join(snap.DNSServers, ", ")), elapsed}, nil
	}
	return Result{"L7", "Résolution DNS (résolveur système)", StatusOK,
		fmt.Sprintf("%s -> %s en %s", name, strings.Join(addrs, ", "), elapsed), elapsed}, addrs
}

// checkDNSConsistency interroge des résolveurs publics de référence
// (Cloudflare, Google) en direct et compare avec la résolution système :
// une divergence peut signaler un hijacking DNS, une pollution de cache,
// ou — légitimement — un split-horizon DNS interne à documenter.
func checkDNSConsistency(name string, systemDNS []string, timeout time.Duration) Result {
	start := time.Now()
	publicResolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}

	systemIPs, sysErr := resolveViaSystem(name, timeout)
	var mismatches []string
	var anyPublicOK bool

	for _, srv := range publicResolvers {
		ips, err := resolveViaServer(name, srv, timeout)
		if err != nil {
			continue
		}
		anyPublicOK = true
		if sysErr == nil && !sameIPSet(systemIPs, ips) {
			mismatches = append(mismatches, fmt.Sprintf("%s -> %s", srv, strings.Join(ips, ",")))
		}
	}

	elapsed := time.Since(start)
	if !anyPublicOK {
		return Result{"L7", "Cohérence DNS multi-résolveur", StatusSkip,
			"Résolveurs publics (1.1.1.1, 8.8.8.8) injoignables sur le port 53 — probablement bloqué par le firewall d'entreprise (normal en environnement contrôlé).",
			elapsed}
	}
	if sysErr != nil {
		return Result{"L7", "Cohérence DNS multi-résolveur", StatusSkip,
			"Résolution système indisponible pour comparaison.", elapsed}
	}
	if len(mismatches) == 0 {
		return Result{"L7", "Cohérence DNS multi-résolveur", StatusOK,
			fmt.Sprintf("Résolution cohérente entre résolveur système (%s) et résolveurs publics.", strings.Join(systemIPs, ",")),
			elapsed}
	}
	return Result{"L7", "Cohérence DNS multi-résolveur", StatusWarning,
		fmt.Sprintf("Divergence détectée — système: %s ; %s. Vérifier si volontaire (split-horizon/DNS interne, load-balancer GeoDNS) ou suspect (hijacking, cache empoisonné).",
			strings.Join(systemIPs, ","), strings.Join(mismatches, " ; ")), elapsed}
}

func resolveViaSystem(name string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(ctx, name)
	if err != nil {
		return nil, err
	}
	sort.Strings(ips)
	return ips, nil
}

func resolveViaServer(name, server string, timeout time.Duration) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, server)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := r.LookupHost(ctx, name)
	if err != nil {
		return nil, err
	}
	sort.Strings(ips)
	return ips, nil
}

func sameIPSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// checkHTTPS effectue la requête HTTPS et retourne en plus l'horodatage
// serveur (en-tête Date) pour permettre le test de dérive d'horloge.
func checkHTTPS(host string, timeout time.Duration) (Result, *time.Time) {
	start := time.Now()
	url := "https://" + host
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	elapsed := time.Since(start)
	if err != nil {
		return Result{"L7", "HTTPS + certificat TLS", StatusFail,
			fmt.Sprintf("Requête vers %s échouée (%v) : proxy/firewall applicatif, DPI, ou service down.", url, err), elapsed}, nil
	}
	defer resp.Body.Close()

	var serverDate *time.Time
	if d := resp.Header.Get("Date"); d != "" {
		if t, err := http.ParseTime(d); err == nil {
			serverDate = &t
		}
	}

	certInfo := "certificat non vérifié"
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		remaining := time.Until(cert.NotAfter)
		if remaining < 0 {
			return Result{"L7", "HTTPS + certificat TLS", StatusWarning,
				fmt.Sprintf("Connexion OK mais certificat expiré depuis %s.", -remaining), elapsed}, serverDate
		}
		certInfo = fmt.Sprintf("certificat valide, expire dans %d jours", int(remaining.Hours()/24))
		_ = tls.VersionTLS12
	}
	return Result{"L7", "HTTPS + certificat TLS", StatusOK,
		fmt.Sprintf("HTTP %d depuis %s, %s (%s)", resp.StatusCode, url, certInfo, elapsed), elapsed}, serverDate
}

// checkClockSkew compare l'horloge locale à l'en-tête Date d'une réponse
// HTTPS de référence. Un décalage important casse silencieusement TLS
// (validation de certificat), Kerberos et 802.1X — cause de panne
// fréquente et rarement vérifiée en premier.
func checkClockSkew(serverDate time.Time) Result {
	start := time.Now()
	skew := time.Since(serverDate)
	if skew < 0 {
		skew = -skew
	}
	detail := fmt.Sprintf("Horloge locale vs serveur de référence : décalage de %s.", skew.Round(time.Second))
	if skew > 5*time.Minute {
		return Result{"L7", "Dérive d'horloge système", StatusWarning,
			detail + " Un décalage > 5 min peut faire échouer TLS, Kerberos, 802.1X. Vérifier NTP.", time.Since(start)}
	}
	return Result{"L7", "Dérive d'horloge système", StatusOK, detail, time.Since(start)}
}

// Print affiche le rapport de façon lisible, dans l'ordre du modèle OSI.
func (r *Report) Print() {
	fmt.Println("=== Pipeline de diagnostic OSI ===")
	fmt.Println()
	worst := StatusOK
	for _, res := range r.Results {
		symbol := "OK"
		switch res.Status {
		case StatusFail:
			symbol = "FAIL"
			worst = StatusFail
		case StatusWarning:
			symbol = "WARN"
			if worst != StatusFail {
				worst = StatusWarning
			}
		case StatusSkip:
			symbol = "SKIP"
		}
		fmt.Printf("[%-4s] %-8s %-32s %s\n", symbol, res.Layer, res.Test, res.Detail)
	}
	fmt.Println()
	if r.StoppedAt != "" {
		fmt.Printf(">>> Pipeline interrompu à la couche %s : corriger ce point avant d'aller plus loin.\n", r.StoppedAt)
		return
	}
	switch worst {
	case StatusFail:
		fmt.Println(">>> Verdict global : ECHEC — au moins un test bloquant a échoué, voir détails ci-dessus.")
	case StatusWarning:
		fmt.Println(">>> Verdict global : ATTENTION — le réseau fonctionne mais des points méritent vérification.")
	default:
		fmt.Println(">>> Verdict global : OK — chaîne L1 à L7 fonctionnelle sur les tests effectués.")
	}
}
