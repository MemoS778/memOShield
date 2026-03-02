import threading
import datetime
import logging

try:
    from scapy.all import sniff, PcapWriter
except Exception:
    sniff = None
    PcapWriter = None

class PCAPRecorder:
    def __init__(self, filename=None, iface=None):
        self.filename = filename or f"capture_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pcap"
        self.iface = iface
        self._thread = None
        self._writer = None

    def start(self, filter_expr=None):
        if sniff is None or PcapWriter is None:
            logging.warning('scapy not available; PCAP recording disabled')
            return
        self._writer = PcapWriter(self.filename, append=True, sync=True)
        self._thread = threading.Thread(target=self._sniff_thread, args=(filter_expr,), daemon=True)
        self._thread.start()
        logging.info('PCAPRecorder started -> %s', self.filename)

    def _sniff_thread(self, filter_expr):
        try:
            sniff(iface=self.iface, filter=filter_expr, prn=lambda pkt: self._writer.write(pkt))
        except RuntimeError as e:
            if 'winpcap' in str(e).lower() or 'layer 2' in str(e).lower():
                logging.warning('Packet capture not available on this OS (requires WinPcap/Npcap on Windows or libpcap on Linux)')
            else:
                logging.error('PCAP error: %s', e)
        except Exception as e:
            logging.error('PCAP thread error: %s', e)
