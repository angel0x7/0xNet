package sniffer

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// Constantes du format de fichier pcap classique (libpcap), compatible
// Wireshark/tcpdump. Pas de dépendance externe : écriture manuelle du
// format binaire (RFC pcap-savefile).
const (
	pcapMagic       = 0xa1b2c3d4
	pcapVersionMaj  = 2
	pcapVersionMin  = 4
	pcapSnapLen     = 65535

	// DLTEthernet : capture Linux (trame Ethernet complète, AF_PACKET).
	DLTEthernet uint32 = 1
	// DLTRaw : capture Windows (IP brut, sans couche Ethernet — SIO_RCVALL).
	DLTRaw uint32 = 101
)

// PCAPWriter écrit un fichier .pcap standard, relisible directement dans
// Wireshark, au fil de la capture (streaming, pas de buffer en mémoire).
type PCAPWriter struct {
	f        *os.File
	linkType uint32
}

// NewPCAPWriter crée (ou écrase) le fichier pcap et écrit l'en-tête global.
func NewPCAPWriter(path string, linkType uint32) (*PCAPWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("création fichier pcap %q échouée: %w", path, err)
	}

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], pcapVersionMaj)
	binary.LittleEndian.PutUint16(hdr[6:8], pcapVersionMin)
	// [8:12] thiszone, [12:16] sigfigs = 0 (non utilisés)
	binary.LittleEndian.PutUint32(hdr[16:20], pcapSnapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], linkType)

	if _, err := f.Write(hdr); err != nil {
		f.Close()
		return nil, fmt.Errorf("écriture en-tête pcap échouée: %w", err)
	}

	return &PCAPWriter{f: f, linkType: linkType}, nil
}

// WritePacket ajoute un paquet au fichier pcap avec un horodatage courant.
func (w *PCAPWriter) WritePacket(data []byte) error {
	now := time.Now()
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[0:4], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(rec[4:8], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(data)))  // taille capturée
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(data))) // taille réelle sur le fil

	if _, err := w.f.Write(rec); err != nil {
		return err
	}
	_, err := w.f.Write(data)
	return err
}

// Close ferme le fichier pcap.
func (w *PCAPWriter) Close() error {
	if w == nil || w.f == nil {
		return nil
	}
	return w.f.Close()
}
