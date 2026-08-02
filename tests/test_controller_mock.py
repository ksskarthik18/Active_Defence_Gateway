import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add controller dir to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))

from adg_controller import ADGController
from policy import Action
from os_ken.lib.packet import packet, ethernet, ipv4

class TestADGController(unittest.TestCase):
    def setUp(self):
        # Create controller instance
        self.controller = ADGController()
        # Mock TrustStore
        self.controller.trust_store = MagicMock()
        # Mock PolicyEngine
        self.controller.policy_engine = MagicMock()
        # Mock logger
        self.controller.logger = MagicMock()
        # Mock FlowInstaller
        self.controller.flow_installer = MagicMock()

    def test_packet_in_handler_ipv4(self):
        # Setup mock event
        ev = MagicMock()
        ev.msg.datapath.id = 1
        ev.msg.match = {"in_port": 1}
        ev.msg.buffer_id = 0xffffffff # NO_BUFFER
        
        # Create a mock packet
        pkt = packet.Packet()
        eth = ethernet.ethernet(dst='00:00:00:00:00:02', src='00:00:00:00:00:01', ethertype=0x0800)
        ip = ipv4.ipv4(src='10.0.0.1', dst='10.0.0.2')
        pkt.add_protocol(eth)
        pkt.add_protocol(ip)
        pkt.serialize()
        ev.msg.data = pkt.data

        # Mock trust score and decision
        self.controller.trust_store.get.return_value = 80
        mock_decision = MagicMock()
        mock_decision.name = "ALLOW"
        mock_decision.__eq__ = lambda self, other: other == Action.ALLOW
        self.controller.policy_engine.evaluate.return_value = mock_decision

        # Run handler
        self.controller.packet_in_handler(ev)

        # Assertions
        self.controller.trust_store.get.assert_called_with('10.0.0.1')
        self.controller.policy_engine.evaluate.assert_called_with(80)

if __name__ == '__main__':
    unittest.main()
