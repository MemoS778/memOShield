package pcap

import (
	"fmt"
	"log"
	"time"
)

// Recorder handles PCAP packet capture.
// Note: For actual packet capture, use gopacket/pcap which requires libpcap.
// This is a placeholder that logs the intent - enable with build tag "pcap".
type Recorder struct {
	Filename string
	Iface    string
	running  bool
}

// New creates a PCAPRecorder.
func New(filename, iface string) *Recorder {
	if filename == "" {
		filename = fmt.Sprintf("capture_%s.pcap", time.Now().UTC().Format("20060102_150405"))
	}
	return &Recorder{
		Filename: filename,
		Iface:    iface,
	}
}

// Start begins packet capture (placeholder - requires gopacket/pcap for real capture).
func (r *Recorder) Start(filterExpr string) {
	log.Printf("PCAPRecorder: capture requested -> %s (gopacket/pcap not linked; placeholder mode)", r.Filename)
	r.running = true
}

// IsRunning returns whether the recorder is active.
func (r *Recorder) IsRunning() bool {
	return r.running
}
