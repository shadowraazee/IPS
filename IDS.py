import time
import logging
import os
from netfilterqueue import NetfilterQueue
import scapy.all as scp

class SimpleFirewall:
    def __init__(self):
        # --- SETTINGS ---
        self.max_syn_requests = 20    # Allowed SYN packets within the interval
        self.max_unique_ports = 10    # Allowed unique ports scanned within the interval
        self.interval_seconds = 5     # Observation timeframe

        #STATE TRACKING
        self.banned_hosts = set()
        self.syn_history = {}
        self.port_history = {}

        #LOGGING SETUP
        # Ensure the log file is created in the same directory as the script
        current_directory = os.path.dirname(os.path.abspath(__file__))
        log_file_path = os.path.join(current_directory, "firewall_alerts.log")
        
        logging.basicConfig(
            filename=log_file_path,
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        print(f"[System] Logging initialized. Writing events to: {log_file_path}")

    def evaluate_syn_rate(self, source_address, destination_address):
        """Checks if a source IP is sending too many SYN requests."""
        current_time = time.time()
        
        # Initialize if not present
        if source_address not in self.syn_history:
            self.syn_history[source_address] = []

        # Filter out timestamps older than our observation interval
        recent_requests = [
            timestamp for timestamp in self.syn_history[source_address] 
            if (current_time - timestamp) < self.interval_seconds
        ]
        
        recent_requests.append(current_time)
        self.syn_history[source_address] = recent_requests

        # Check against threshold
        if len(recent_requests) > self.max_syn_requests:
            if source_address not in self.banned_hosts:
                print(f"[SECURITY ALERT] SYN flood recognized from {source_address}")
                logging.warning(f"DETECTED: SYN flood | Source: {source_address} | Destination: {destination_address}")
                self.banned_hosts.add(source_address)
            return True
            
        return False

    def evaluate_port_scan(self, source_address, target_port, destination_address):
        """Checks if a source IP is scanning too many unique ports."""
        current_time = time.time()
        
        #Initialize if not present
        if source_address not in self.port_history:
            self.port_history[source_address] = {}

        #Remove expired port entries
        active_ports = {
            port: timestamp 
            for port, timestamp in self.port_history[source_address].items() 
            if (current_time - timestamp) < self.interval_seconds
        }
        
        active_ports[target_port] = current_time
        self.port_history[source_address] = active_ports

        # Check against threshold
        if len(active_ports) > self.max_unique_ports:
            if source_address not in self.banned_hosts:
                print(f"[SECURITY ALERT] Port sweep recognized from {source_address}")
                logging.warning(f"DETECTED: Port sweep | Source: {source_address} | Destination: {destination_address} | Target Port: {target_port}")
                self.banned_hosts.add(source_address)
            return True
            
        return False

    def analyze_traffic(self, raw_packet):
        """Main callback for NetfilterQueue packet processing."""
        parsed_ip_layer = scp.IP(raw_packet.get_payload())

        ip_src = parsed_ip_layer.src
        ip_dst = parsed_ip_layer.dst

        # 1. Verify against the ban list
        if ip_src in self.banned_hosts:
            print(f"[ACTION: DROP] Discarding traffic from banned IP {ip_src}")
            logging.info(f"PREVENTED: Dropped packet | Source: {ip_src} | Destination: {ip_dst}")
            raw_packet.drop()
            return

        # 2 Deep dive into TCP traffic
        if parsed_ip_layer.haslayer(scp.TCP):
            tcp_layer = parsed_ip_layer[scp.TCP]

            # Look specifically for SYN flags
            if tcp_layer.flags == "S":
                if self.evaluate_syn_rate(ip_src, ip_dst):
                    logging.info(f"PREVENTED: Dropped SYN packet | Source: {ip_src} | Destination: {ip_dst}")
                    raw_packet.drop()
                    return

                if self.evaluate_port_scan(ip_src, tcp_layer.dport, ip_dst):
                    logging.info(f"PREVENTED: Dropped port scan packet | Source: {ip_src} | Destination: {ip_dst} | Port: {tcp_layer.dport}")
                    raw_packet.drop()
                    return

        # 3 Log UDP traffic passively (Console only, to save disk space)
        elif parsed_ip_layer.haslayer(scp.UDP):
            print(f"[ROUTINE] UDP Datagram: {ip_src} -> {ip_dst}")

        # 4 Let benign traffic pass
        raw_packet.accept()

    def boot(self, queue_number=0):
        """Binds to the specified queue and starts the firewall."""
        print("[System] Engaging intrusion detection modules...")
        nfq_instance = NetfilterQueue()
        nfq_instance.bind(queue_number, self.analyze_traffic)

        try:
            nfq_instance.run()
        except KeyboardInterrupt:
            print("\n[System] Halting operations and unbinding queue...")
            logging.info("System shutting down...")
            nfq_instance.unbind()


if __name__ == "__main__":
    shield = SimpleFirewall()
    shield.boot()