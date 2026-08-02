from policy import Action

class FlowInstaller:
    def __init__(self, logger):
        self.logger = logger

    def install_default_flow(self, datapath, match, actions):
        """Installs the initial table-miss flow (priority 0)"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def install_policy_flow(self, datapath, match, action, msg_buffer_id, out_port=None):
        """Installs a flow rule based on the trust policy Action"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        priority = 0
        hard_timeout = 0
        idle_timeout = 0
        actions = []

        if action == Action.DROP:
            priority = 200
            hard_timeout = 30
            idle_timeout = 10
            # No actions == drop
        elif action == Action.REDIRECT:
            priority = 150
            idle_timeout = 60
            if out_port:
                actions = [parser.OFPActionOutput(out_port)]
        elif action == Action.MIRROR:
            priority = 120
            idle_timeout = 60
            if out_port:
                actions = [parser.OFPActionOutput(out_port)]
        elif action == Action.ALLOW:
            priority = 1
            idle_timeout = 60
            if out_port:
                actions = [parser.OFPActionOutput(out_port)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        kwargs = {
            'datapath': datapath,
            'priority': priority,
            'match': match,
            'instructions': inst,
            'idle_timeout': idle_timeout,
            'hard_timeout': hard_timeout
        }
        
        if msg_buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs['buffer_id'] = msg_buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)
        self.logger.debug("Installed flow: Priority=%s, Action=%s", priority, action.name)
