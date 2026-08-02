from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from policy import Action, PolicyEngine
from trust import TrustStore
from flow import FlowInstaller
from detector import TrustChangeDetector
from utils import get_logger, debug_packet

logger = get_logger("ADG")


class ADGController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    

    def __init__(self, *args, **kwargs):
        super(ADGController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.policy_engine = PolicyEngine()
        self.trust_store = TrustStore()
        self.flow_installer = FlowInstaller(self.logger)
        self.datapaths = {}
        self.detector = TrustChangeDetector(self)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]
        self.flow_installer.install_default_flow(datapath, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        dst = eth.dst
        src = eth.src

        self.logger.info(
            "Switch=%s SRC=%s DST=%s IN=%s",
            dpid,
            src,
            dst,
            in_port
        )

        # Learn source MAC
        self.mac_to_port[dpid][src] = in_port

        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            
            # Register with detector for background monitoring
            self.detector.register_host(src_ip)
            
            trust = self.trust_store.get(src_ip)
            decision = self.policy_engine.evaluate(trust)
            
            priority = 1
            if decision == Action.DROP: priority = 200
            elif decision == Action.REDIRECT: priority = 150
            elif decision == Action.MIRROR: priority = 120
            
            print("[POLICY]")
            print(f"Host : {src_ip}")
            print(f"Trust : {trust}")
            print(f"Decision : {decision.name}")
            print(f"Priority : {priority}\n")
        else:
            decision = Action.ALLOW

        match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

        if decision == Action.DROP:
            # Install high priority drop flow, no PacketOut
            self.flow_installer.install_policy_flow(datapath, match, decision, msg.buffer_id)
            return

        # ALLOW, MIRROR, REDIRECT paths
        # Only install flow if we know the destination port
        if out_port != ofproto.OFPP_FLOOD:
            self.flow_installer.install_policy_flow(datapath, match, decision, msg.buffer_id, out_port=out_port)

        # Send current packet out
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
