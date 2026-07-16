# 0xNetAdmin

Outil de premier diagnostic réseau en Go, pensé pour un professionnel réseau
qui doit rapidement comprendre le contexte réseau d'une machine et localiser
une panne, couche par couche selon le modèle OSI.

**Compatible Linux et Windows**, sans dépendance externe obligatoire (pas de
libpcap/cgo requis). Npcap est utilisé automatiquement s'il est détecté sous
Windows, avec repli propre sinon.

## Build

```bash
go build -o 0xnetadmin .
GOOS=windows GOARCH=amd64 go build -o 0xnetadmin.exe .
```

## Sous-commandes

```
0xnetadmin sniff   [-i eth0] [-proto tcp|udp|icmp|arp] [-port 443] [-n 100] [-t 30s] [-v]
                   [-flows] [-pcap capture.pcap]
0xnetadmin sysinfo [-json] [-out fichier.json] [-save snapshot.json] [-diff ancien.json]
0xnetadmin check   [-i eth0] [-host www.google.com] [-ports 443,80,22] [-stop-on-fail]
                   [-json] [-out rapport.json]
0xnetadmin trace   [-max-hops 30] [-probes 3] [-timeout 1s] <host>
0xnetadmin ping    [-timeout 2s] <host>
```

> Les options se placent **avant** l'argument positionnel (`<host>`), comme
> pour tout outil basé sur le package `flag` de Go.

### `sysinfo` — contexte réseau + export JSON + diff de snapshot

```bash
./0xnetadmin sysinfo                        # affichage texte
./0xnetadmin sysinfo -json                  # export JSON (stdout)
./0xnetadmin sysinfo -json -out snap.json   # export JSON (fichier)
./0xnetadmin sysinfo -save avant.json       # snapshot de référence
./0xnetadmin sysinfo -diff avant.json       # diff avec l'état actuel
```

Le JSON est directement collable dans un ticket ou ingérable par un SIEM.
Le mode `-diff` compare deux snapshots et signale : passerelle par défaut
changée, interface passée UP/DOWN, adresses IP modifiées, route par défaut
ajoutée/supprimée, résolveurs DNS changés, et **conflits ARP potentiels**
(une IP répond soudain avec une MAC différente).

### `check` — pipeline de diagnostic OSI (L1 → L7), avec export JSON

```bash
./0xnetadmin check
./0xnetadmin check -host intranet.entreprise.local -ports 443,80,22,3389 -json -out rapport.json
```

| Couche | Test | Détail |
|---|---|---|
| L1/L2 | Interface UP, MTU, adresses | |
| L1/L2 | Compteurs d'erreurs interface | `/sys/class/net/*/statistics` (Linux) ou `Get-NetAdapterStatistics` via PowerShell (Windows) |
| L2 | Résolution ARP de la passerelle | |
| L3 | Présence d'une route par défaut | |
| L3 | Passerelles par défaut multiples | détecte un routage asymétrique / conflit VPN-split-tunnel |
| L3 | Ping de la passerelle | ping ICMP natif Go, repli sur le binaire système si droits insuffisants |
| L3 | Path MTU Discovery | recherche **dichotomique** (ping DF bit) entre 1200 et 1472 octets |
| L4 | Connexion TCP par port (liste configurable) | classe chaque échec **REFUSED** (RST) vs **FILTERED** (timeout) |
| L7 | Résolution DNS (résolveur système) | |
| L7 | Cohérence DNS multi-résolveur | compare résolveur système vs 1.1.1.1 / 8.8.8.8 |
| L7 | HTTPS + certificat TLS | |
| L7 | Dérive d'horloge système | via l'en-tête `Date` HTTP |

### `trace` — traceroute intégré avec analyse par saut

```bash
sudo ./0xnetadmin trace -max-hops 20 -probes 3 github.com
```

Implémentation ICMP native en Go (pas de dépendance au binaire `traceroute`/
`tracert`). Envoie plusieurs sondes par saut (TTL croissant) et affiche pour
chacun : adresse répondante, latence min/avg/max, taux de perte — comme un
traceroute professionnel, avec la destination finale marquée explicitement.

### `ping` — ping ICMP natif

```bash
sudo ./0xnetadmin ping 192.168.1.1
```

Implémentation ICMP Echo Request/Reply en Go pur (`internal/nettools`),
sans dépendance au binaire `ping` système. Nécessite les mêmes droits qu'un
ping classique (root/CAP_NET_RAW sous Linux, Administrateur sous Windows).
Utilisé en interne par `check` (avec repli automatique sur le binaire
système si le raw socket n'est pas accessible).

### `sniff` — capture, agrégation de flux, export PCAP

```bash
# capture paquet par paquet (comportement historique)
sudo ./0xnetadmin sniff -i eth0 -proto tcp -port 443

# agrégation par flux 5-tuple ("qui parle à qui")
sudo ./0xnetadmin sniff -i eth0 -flows -t 30s

# export au format pcap standard, relisible dans Wireshark
sudo ./0xnetadmin sniff -i eth0 -pcap capture.pcap -t 60s
```

- **Linux** : capture Ethernet complète (AF_PACKET), ARP inclus.
- **Windows** : capture Ethernet complète si **Npcap** est installé
  (détection et repli automatiques, chargement dynamique de `wpcap.dll` —
  aucune dépendance de build) ; sinon capture IPv4 uniquement via raw
  socket + `SIO_RCVALL` (pas d'Ethernet/ARP), limitation native de Winsock.

Le fichier `.pcap` généré utilise le link-type adapté au moteur de capture
actif (Ethernet ou IP brut) et s'ouvre directement dans Wireshark/tcpdump.

## Architecture

```
0xNetAdmin/
├── main.go                            # CLI (sniff / sysinfo / check / trace / ping)
├── internal/
│   ├── nettools/
│   │   ├── icmp.go                    # ping ICMP natif (Go pur, cross-OS)
│   │   ├── traceroute.go              # traceroute + analyse par saut
│   │   ├── ttl_linux.go               # réglage TTL socket (Linux)
│   │   └── ttl_windows.go             # réglage TTL socket (Windows)
│   ├── sysinfo/
│   │   ├── sysinfo.go                 # types communs + Collect() (portable)
│   │   ├── sysinfo_linux.go           # routes/DNS/ARP via /proc/net/*
│   │   ├── sysinfo_windows.go         # routes/DNS/ARP via route print / ipconfig / arp -a
│   │   └── diff.go                    # export JSON, Save/Load, Diff de snapshots
│   ├── sniffer/
│   │   ├── common.go                  # décodage L2-L7 + agrégation de flux (5-tuple)
│   │   ├── pcap.go                    # écriture de fichiers .pcap standard
│   │   ├── sniffer_linux.go           # capture AF_PACKET
│   │   ├── sniffer_windows.go         # capture Npcap ou repli SIO_RCVALL
│   │   └── npcap_windows.go           # FFI wpcap.dll (chargement dynamique)
│   └── diagnostics/diagnostics.go     # pipeline de tests L1->L7, export JSON
```

## Limites connues / pistes restantes

- Npcap : code écrit et compilé (cross-compilation Windows validée), mais
  non exécuté faute d'environnement Windows+Npcap disponible pour ce
  développement — à valider en conditions réelles avant usage critique.
- Path MTU Discovery et traceroute utilisent ICMP : inefficaces si un
  pare-feu bloque totalement l'ICMP sortant (le test bascule alors en
  `SKIP` plutôt que de donner un faux résultat).
- Agrégation de flux : uniquement en mémoire pour la durée de la capture
  (pas de export flux au format NetFlow/IPFIX à ce stade).
