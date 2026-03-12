"""
Water Treatment Plant — Mininet Network Topology

Mirrors the physical lab network:
  TP-Link LS1005G switch connecting PLC1, PLC2, SCADA PC, and attacker.
"""

from mininet.topo import Topo
from mininet.nodelib import LinuxBridge

from utils import (
    PLC1_ADDR, PLC2_ADDR, SCADA_ADDR, ATTACKER_ADDR, NETMASK
)

# Use LinuxBridge instead of OVSSwitch to avoid needing an OpenFlow controller
DEFAULT_SWITCH = LinuxBridge


class PlantTopo(Topo):
    """Star topology matching the lab's LS1005G switch layout."""

    def build(self):

        # LS1005G switch (LinuxBridge — no OpenFlow controller needed)
        switch = self.addSwitch('s1', cls=LinuxBridge)

        # PLC 1 — Process Controller (Arduino Mega + W5500)
        plc1 = self.addHost(
            'plc1',
            ip=PLC1_ADDR + NETMASK,
            mac='00:00:00:00:01:20'
        )

        # PLC 2 — Sensor Node (Arduino Uno + MAX485)
        # In hardware this uses RS-485; in simulation we use TCP
        plc2 = self.addHost(
            'plc2',
            ip=PLC2_ADDR + NETMASK,
            mac='00:00:00:00:01:21'
        )

        # SCADA / HMI monitoring station
        scada = self.addHost(
            'scada',
            ip=SCADA_ADDR + NETMASK,
            mac='00:00:00:00:01:10'
        )

        # Attacker workstation
        attacker = self.addHost(
            'attacker',
            ip=ATTACKER_ADDR + NETMASK,
            mac='00:00:00:00:01:99'
        )

        # All hosts connect to the switch
        self.addLink(plc1, switch)
        self.addLink(plc2, switch)
        self.addLink(scada, switch)
        self.addLink(attacker, switch)
