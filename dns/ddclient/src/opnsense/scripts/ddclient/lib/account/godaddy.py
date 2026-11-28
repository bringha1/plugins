"""
    Copyright (c) 2026 
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
"""
import syslog
import requests
from . import BaseAccount


class Godaddy(BaseAccount):
    _services = {'godaddy': 'GoDaddy'}

    def __init__(self, account: dict):
        super().__init__(account)

    @staticmethod
    def known_services():
        return Godaddy._services

    @staticmethod
    def match(account):
        return account.get('service') in Godaddy._services

    def execute(self):
        """ GoDaddy DNS update
        """
        if super().execute():
            ip = str(self.current_address)
            record_type = 'AAAA' if ':' in ip else 'A'
            zone = self.settings.get('zone', '').strip()
            wildcard = str(self.settings.get('wildcard', '0')) == '1'

            try:
                ttl = max(600, int(self.settings.get('ttl') or 600))
            except (ValueError, TypeError):
                ttl = 600

            # API-Key (Username) und Secret (Password)
            headers = {
                'Authorization': f"sso-key {self.settings.get('username')}:{self.settings.get('password')}",
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }

            hostnames = [h.strip() for h in self.settings.get('hostnames', '').split(',') if h.strip()]

            for hostname in hostnames:
                # Fallback, falls das Zone-Feld in der GUI leer gelassen wurde
                target_zone = zone
                if not target_zone:
                    parts = hostname.split('.')
                    target_zone = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

                # Subdomain aus FQDN extrahieren (z.B. '://example.com' -> 'vpn', Root -> '@')
                if hostname == target_zone:
                    record_name = '@'
                elif target_zone and hostname.endswith(f".{target_zone}"):
                    record_name = hostname[:-(len(target_zone) + 1)]
                else:
                    record_name = hostname

                records = [record_name]
                if wildcard:
                    wc_record = '*' if record_name == '@' else f"*.{record_name}"
                    records.append(wc_record)

                for rec in records:
                    url = f"https://api.godaddy.com/v1/domains/{target_zone}/records/{record_type}/{rec}"
                    payload = [
                        {
                            'data': ip,
                            'ttl': ttl
                        }
                    ]
                    try:
                        response = requests.put(url, json=payload, headers=headers, timeout=15)
                        if response.status_code != 200:
                            raise RuntimeError(
                                f"GoDaddy update failed for {self.description} ({hostname} -> {ip}): "
                                f"HTTP {response.status_code} - {response.text}"
                            )
                    except Exception as e:
                        syslog.syslog(syslog.LOG_ERR, str(e))
                        return False

            syslog.syslog(
                syslog.LOG_NOTICE,
                f"Account {self.description} set new ip {ip} for hostnames {','.join(hostnames)}"
            )
            self.update_state(address=self.current_address)
            return True
        return False
