import logging
import socket
import requests
from .config import GEOIP_URL

class GeoIPClient:
    """IP adresi için coğrafi konum, ISP ve hostname bilgisi sağlar."""

    def __init__(self, api_url=None):
        self.url = api_url or GEOIP_URL

    def lookup(self, ip):
        """IP adresinden ülke, koordinat, ISP ve hostname bilgisi döndürür."""
        result = {
            'country': 'Unknown',
            'lat': None,
            'lon': None,
            'isp': 'Unknown',
            'org': 'Unknown',
            'hostname': 'Unknown',
        }
        # GeoIP + ISP bilgisi (ipapi.co tek istekte hepsini döndürür)
        try:
            r = requests.get(self.url.format(ip=ip), timeout=3)
            if r.status_code == 200:
                data = r.json()
                result['country'] = data.get('country_name') or data.get('country') or 'Unknown'
                result['lat'] = data.get('latitude') or data.get('lat')
                result['lon'] = data.get('longitude') or data.get('lon')
                result['isp'] = data.get('org') or data.get('isp') or 'Unknown'
                result['org'] = data.get('org') or 'Unknown'
        except Exception as e:
            logging.debug('GeoIP lookup failed: %s', e)

        # Reverse DNS ile hostname çözümleme
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result['hostname'] = hostname
        except (socket.herror, socket.gaierror, OSError):
            result['hostname'] = ip  # çözümlenemezse IP'yi kullan

        return result
