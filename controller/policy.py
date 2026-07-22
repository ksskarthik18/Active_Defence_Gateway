"""
policy.py

Active Defense Gateway Policy Engine

This module contains all security decision logic.
The controller should NEVER make security decisions directly.
"""

from enum import Enum, auto


class Action(Enum):
    ALLOW = auto()
    DROP = auto()
    MIRROR = auto()      # Future IDS support
    REDIRECT = auto()    # Future Honeypot support


class PolicyEngine:

    def __init__(self):
        self.blacklist = set()
        self.whitelist = set()

    def add_to_blacklist(self, mac):
        self.blacklist.add(mac)

    def remove_from_blacklist(self, mac):
        self.blacklist.discard(mac)

    def add_to_whitelist(self, mac):
        self.whitelist.add(mac)

    def evaluate(self, src, dst, in_port):

        # Highest priority
        if src in self.blacklist:
            return Action.DROP

        # Future rules go here

        return Action.ALLOW