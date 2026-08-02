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


class PolicyConfig:
    ALLOW = 90
    LOG = 70
    MIRROR = 40
    REDIRECT = 20

class PolicyEngine:
    def evaluate(self, trust: int) -> Action:
        if trust >= PolicyConfig.ALLOW:
            return Action.ALLOW
            
        elif trust >= PolicyConfig.LOG:
            # For 70 <= trust < 90, log internally but ALLOW
            # In a real implementation this would emit a log event.
            return Action.ALLOW
            
        elif trust >= PolicyConfig.MIRROR:
            return Action.MIRROR
            
        elif trust >= PolicyConfig.REDIRECT:
            return Action.REDIRECT
            
        else:
            return Action.DROP