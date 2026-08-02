import time
import datetime
from os_ken.lib import hub
from policy import Action

class TrustChangeDetector:
    def __init__(self, controller):
        self.controller = controller
        self.host_policy = {}
        self.known_hosts = set()
        self.monitor_thread = hub.spawn(self._monitor)
        
    def register_host(self, ip):
        """Register an IP to be monitored by the background thread"""
        if ip not in self.known_hosts:
            self.known_hosts.add(ip)
            # Initialize with ALLOW so any immediate policy applies instantly
            self.host_policy[ip] = Action.ALLOW

    def _monitor(self):
        """Background loop querying the eBPF map for trust changes"""
        while True:
            hub.sleep(2) # Monitor every 2 seconds
            
            # Use datapath 1 for installing global flows (assumes a single switch or we need all datapaths)
            # In a real environment, you iterate over active datapaths
            datapaths = list(self.controller.datapaths.keys())
            if not datapaths:
                continue

            for ip in list(self.known_hosts):
                trust = self.controller.trust_store.get(ip)
                new_action = self.controller.policy_engine.evaluate(trust)
                old_action = self.host_policy.get(ip, Action.ALLOW)
                
                if new_action != old_action:
                    # Policy transition detected
                    print("\n[TRUST UPDATE]")
                    print(f"Host        : {ip}")
                    # Note: We don't have historical old_trust without caching it, so we just log the new trust
                    print(f"Trust       : {trust}")
                    print(f"Policy      : {old_action.name} -> {new_action.name}")
                    print(f"Time        : {datetime.datetime.now().strftime('%H:%M:%S')}\n")
                    
                    # Update cache
                    self.host_policy[ip] = new_action
                    
                    # Enforce across all connected switches
                    for dpid in datapaths:
                        dp = self.controller.datapaths.get(dpid)
                        if dp:
                            self.controller.flow_installer.install_ip_policy_flow(dp, ip, new_action)
