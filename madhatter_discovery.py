#!/usr/bin/env python3

import subprocess
import shutil
import os
import signal
import socket
import time

class DiscoveryManager:
    """
    Manages Avahi/mDNS discovery for Madhatter.
    Uses CLI tools (avahi-publish, avahi-browse) to avoid extra Python dependencies.
    """

    SERVICE_TYPE = "_madhatter._tcp"

    def __init__(self):
        self.publish_process = None
        self.hostname = socket.gethostname()

    def is_available(self):
        """Check if avahi-utils are installed."""
        return (shutil.which("avahi-publish") is not None and 
                shutil.which("avahi-browse") is not None)

    def start_advertising(self):
        """
        Publish the _madhatter._tcp service on port 22 using avahi-publish.
        Runs in the background.
        """
        if self.publish_process or not self.is_available():
            return

        user = os.environ.get("USER", "unknown")
        # Format: "Madhatter (user@hostname)"
        # Note: Avahi uses this as the user-friendly service name.
        service_name = f"Madhatter ({user}@{self.hostname})"

        # avahi-publish -s <name> <type> <port> [txt...]
        cmd = ["avahi-publish", "-s", service_name, self.SERVICE_TYPE, "22"]
        
        try:
            self.publish_process = subprocess.Popen(
                cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

    def stop_advertising(self):
        """Stop the avahi-publish process."""
        if self.publish_process:
            self.publish_process.terminate()
            try:
                self.publish_process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.publish_process.kill()
            self.publish_process = None

    def browse_peers(self, timeout=3):
        """
        Scan for Madhatter peers using avahi-browse -r -p -t.
        Returns a list of dicts with resolved info.
        """
        if not self.is_available():
            return []

        # -r: resolve services to IP/hostname
        # -p: parsable output (easy to split by ';')
        # -t: terminate after dumping cache (fast snapshot)
        # Note: avahi-browse -t might return quickly, sometimes needs a moment.
        # Ideally, we run it for a few seconds. -t terminates when cache is dumped. 
        # But for mDNS, cache might be empty initially.
        # A better approach for a "Scan" button is to run for a fixed duration.
        
        # We'll use timeout to kill it if it hangs, but rely on -t to exit.
        cmd = ["avahi-browse", "-r", "-p", "-t", self.SERVICE_TYPE]
        
        peers = []
        try:
            # shell=False to avoid injection, capture output
            result = subprocess.check_output(cmd, timeout=timeout).decode('utf-8', errors='ignore')
            
            # Parsable format example (fields separated by ;):
            # =;eth0;IPv4;Service Name;_madhatter._tcp;local;hostname.local;192.168.1.50;22;"txt"
            
            for line in result.splitlines():
                if not line.startswith('='):
                    continue
                    
                parts = line.split(';')
                if len(parts) < 8:
                    continue
                    
                # Index 2: Protocol (IPv4/IPv6)
                protocol = parts[2]
                if protocol != "IPv4":
                    continue # Focus on IPv4 for simplicity

                # Index 3: Service Name (e.g. "Madhatter (bob@host)")
                s_name = parts[3]
                
                # Index 6: Hostname (e.g. "host.local")
                s_host = parts[6]
                
                # Index 7: IP Address
                s_addr = parts[7]
                
                # Index 8: Port
                s_port = parts[8]

                # Filter out ourselves (simple check against hostname)
                if s_host.startswith(self.hostname):
                    continue

                # Extract user from service name if possible
                user = "unknown"
                if "(" in s_name and "@" in s_name:
                    try:
                        user = s_name.split('(')[1].split('@')[0]
                    except IndexError:
                        pass
                
                peers.append({
                    'service_name': s_name,
                    'hostname': s_host,
                    'ip': s_addr,
                    'port': s_port,
                    'user': user
                })

        except subprocess.TimeoutExpired:
            pass # Use whatever we found
        except Exception:
            pass

        # Deduplicate by IP/Service Name
        unique_peers = {p['ip']: p for p in peers}.values()
        return list(unique_peers)

if __name__ == "__main__":
    dm = DiscoveryManager()
    if dm.is_available():
        print("Avahi Available. Starting Ad...")
        dm.start_advertising()
        time.sleep(2)
        print("Browsing...")
        found = dm.browse_peers()
        print(f"Found: {found}")
        dm.stop_advertising()
    else:
        print("Avahi tools missing.")
