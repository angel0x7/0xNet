// 0xNetAdmin — outil de premier diagnostic réseau pour professionnels.
//
// Sous-commandes :
//
//	sniff      Capture et décode les paquets couche par couche (OSI L2-L7)
//	sysinfo    Affiche le contexte réseau complet de la machine
//	check      Exécute le pipeline de diagnostic OSI (L1 -> L7)
//	trace      Traceroute avec analyse de latence/perte par saut
//	ping       Ping ICMP natif (sans dépendance au binaire système)
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"0xnetadmin/internal/diagnostics"
	"0xnetadmin/internal/nettools"
	"0xnetadmin/internal/sniffer"
	"0xnetadmin/internal/sysinfo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "sniff":
		cmdSniff(os.Args[2:])
	case "sysinfo":
		cmdSysinfo(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	case "trace", "traceroute":
		cmdTrace(os.Args[2:])
	case "ping":
		cmdPing(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "commande inconnue : %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`0xNetAdmin — outil de diagnostic réseau (modèle OSI)

Usage:
  0xnetadmin sniff   [-i eth0] [-proto tcp|udp|icmp|arp] [-port 443] [-n 100] [-t 30s] [-v]
                     [-flows] [-pcap capture.pcap]
  0xnetadmin sysinfo [-json] [-out fichier.json] [-save snapshot.json] [-diff ancien.json]
  0xnetadmin check   [-i eth0] [-host www.google.com] [-ports 443,80,22] [-stop-on-fail]
                     [-json] [-out rapport.json]
  0xnetadmin trace   [-max-hops 30] [-probes 3] [-timeout 1s] <host>
  0xnetadmin ping    [-timeout 2s] <host>

Exemples:
  sudo 0xnetadmin sniff -i eth0 -flows
  sudo 0xnetadmin sniff -i eth0 -pcap capture.pcap -proto tcp -port 443
  0xnetadmin sysinfo -save avant.json
  0xnetadmin sysinfo -diff avant.json
  0xnetadmin check -host intranet.entreprise.local -json -out rapport.json
  0xnetadmin trace -max-hops 20 github.com`)
}

func cmdSniff(args []string) {
	fs := flag.NewFlagSet("sniff", flag.ExitOnError)
	iface := fs.String("i", "", "interface à écouter (vide = première interface non-loopback rencontrée)")
	proto := fs.String("proto", "", "filtre protocole : tcp, udp, icmp, arp")
	port := fs.Int("port", 0, "filtre sur un port (source ou destination)")
	maxPkts := fs.Int("n", 0, "nombre max de paquets (0 = illimité)")
	duration := fs.Duration("t", 0, "durée max de capture, ex: 30s (0 = illimité)")
	verbose := fs.Bool("v", false, "affichage verbeux (taille payload)")
	flows := fs.Bool("flows", false, "agrège par flux 5-tuple au lieu d'afficher paquet par paquet")
	pcapFile := fs.String("pcap", "", "exporte la capture au format .pcap (relisible dans Wireshark)")
	fs.Parse(args)

	opts := sniffer.Options{
		Iface:          *iface,
		MaxPackets:     *maxPkts,
		Duration:       *duration,
		Verbose:        *verbose,
		AggregateFlows: *flows,
		PCAPFile:       *pcapFile,
		Filter: sniffer.Filter{
			Proto: *proto,
			Port:  *port,
		},
	}

	s, err := sniffer.New(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur :", err)
		os.Exit(1)
	}
	defer s.Close()

	if runtime.GOOS == "windows" {
		if npcapSniffer, ok := interface{}(s).(interface{ UsingNpcap() bool }); ok && npcapSniffer.UsingNpcap() {
			fmt.Println("[Windows] Capture Ethernet complète via Npcap (ARP inclus).")
		} else {
			fmt.Println("[Windows] Npcap non détecté : capture IPv4 uniquement (raw socket + SIO_RCVALL), pas d'Ethernet/ARP. Installer Npcap pour une capture complète.")
		}
	}
	if *pcapFile != "" {
		fmt.Printf("Export pcap vers %s (relecture possible dans Wireshark)\n", *pcapFile)
	}
	fmt.Println("Capture en cours... (Ctrl+C pour arrêter)")
	if err := s.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Erreur pendant la capture :", err)
	}

	st := s.Stats()
	fmt.Printf("\n--- Statistiques ---\nTotal=%d  ARP=%d  IPv4=%d  IPv6=%d  TCP=%d  UDP=%d  ICMP=%d  Autres=%d  Octets=%d\n",
		st.Total, st.ARP, st.IPv4, st.IPv6, st.TCP, st.UDP, st.ICMP, st.Other, st.Bytes)
}

func cmdSysinfo(args []string) {
	fs := flag.NewFlagSet("sysinfo", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "sortie JSON au lieu du format texte")
	outFile := fs.String("out", "", "écrit la sortie dans un fichier au lieu de stdout")
	saveFile := fs.String("save", "", "sauvegarde le snapshot en JSON pour un diff ultérieur")
	diffFile := fs.String("diff", "", "compare le snapshot actuel à un snapshot sauvegardé précédemment")
	fs.Parse(args)

	snap, err := sysinfo.Collect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur :", err)
		os.Exit(1)
	}

	if *diffFile != "" {
		before, err := sysinfo.Load(*diffFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Erreur :", err)
			os.Exit(1)
		}
		diffs := sysinfo.Diff(before, snap)
		sysinfo.PrintDiff(diffs)
		if *saveFile != "" {
			if err := snap.Save(*saveFile); err != nil {
				fmt.Fprintln(os.Stderr, "Erreur sauvegarde :", err)
			}
		}
		return
	}

	if *saveFile != "" {
		if err := snap.Save(*saveFile); err != nil {
			fmt.Fprintln(os.Stderr, "Erreur sauvegarde :", err)
			os.Exit(1)
		}
		fmt.Printf("Snapshot sauvegardé dans %s\n", *saveFile)
		return
	}

	if *jsonOut || *outFile != "" {
		data, err := snap.ToJSON()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Erreur JSON :", err)
			os.Exit(1)
		}
		writeOutput(data, *outFile)
		return
	}

	snap.Print()
}

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	iface := fs.String("i", "", "interface à cibler en priorité")
	host := fs.String("host", "", "hôte HTTPS/DNS à tester (défaut www.google.com)")
	ports := fs.String("ports", "443,80", "ports TCP à tester, séparés par des virgules")
	stopOnFail := fs.Bool("stop-on-fail", false, "arrêter le pipeline au premier échec bloquant")
	jsonOut := fs.Bool("json", false, "sortie JSON au lieu du format texte")
	outFile := fs.String("out", "", "écrit la sortie dans un fichier au lieu de stdout")
	fs.Parse(args)

	var portList []int
	for _, p := range strings.Split(*ports, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil {
			portList = append(portList, n)
		}
	}

	report := diagnostics.Run(diagnostics.Options{
		Iface:       *iface,
		TargetHost:  *host,
		Ports:       portList,
		PingTimeout: 2 * time.Second,
		StopOnFail:  *stopOnFail,
	})

	if *jsonOut || *outFile != "" {
		data, err := report.ToJSON()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Erreur JSON :", err)
			os.Exit(1)
		}
		writeOutput(data, *outFile)
		return
	}

	report.Print()
}

func cmdTrace(args []string) {
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	maxHops := fs.Int("max-hops", 30, "nombre maximum de sauts")
	probes := fs.Int("probes", 3, "sondes envoyées par saut")
	timeout := fs.Duration("timeout", 1*time.Second, "délai d'attente par sonde")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: 0xnetadmin trace [-max-hops 30] [-probes 3] [-timeout 1s] <host>")
		os.Exit(1)
	}
	host := fs.Arg(0)

	hops, err := nettools.Traceroute(host, *maxHops, *probes, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur :", err)
		os.Exit(1)
	}
	nettools.PrintTraceroute(host, hops)
}

func cmdPing(args []string) {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	timeout := fs.Duration("timeout", 2*time.Second, "délai d'attente")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: 0xnetadmin ping [-timeout 2s] <host>")
		os.Exit(1)
	}
	host := fs.Arg(0)

	res, err := nettools.Ping(host, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur :", err)
		os.Exit(1)
	}
	fmt.Printf("Réponse de %s : temps=%s\n", res.From, res.RTT.Round(time.Microsecond))
}

// writeOutput écrit sur stdout, ou dans un fichier si path est renseigné.
func writeOutput(data []byte, path string) {
	if path == "" {
		fmt.Println(string(data))
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "Erreur écriture fichier :", err)
		os.Exit(1)
	}
	fmt.Printf("Rapport écrit dans %s\n", path)
}