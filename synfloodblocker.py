# coding=utf-8

# Based on: https://github.com/noxrepo/pox/blob/carp/pox/misc/of_tutorial.py

# Original work Copyright 2012 James McCauley
# Modified work Copyright 2017 Fardjad Davari
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Place this file in the misc folder in a POX distribution and use the 
# following command to run it:
# ./pox.py py --completion log.level --DEBUG misc.synfloodblocker

import pox.openflow.libopenflow_01 as of

from pox.core import core
from pox.lib.packet.ipv4 import ipv4
from pox.lib.util import dpidToStr

log = core.getLogger()

# constants
AVG_NUM_OF_CONN = 3
MIN_NUM_OF_PACKETS_PER_CONN = 5

TEMP_IDLE_TIMEOUT = 15
TEMP_HARD_TIMEOUT = 30

FREQ_IDLE_TIMEOUT = 300
FREQ_HARD_TIMEOUT = 600

EVIL_IDLE_TIMEOUT = 300
EVIL_HARD_TIMEOUT = 600

DL_TYPE_IPV4 = 0x0800

STATUS_BLOCKED = 'BLOCKED'
STATUS_ALLOWED = 'ALLOWED'
STATUS_UNKNOWN = 'UNKNOWN'

# globals
ip_to_c = {}
ip_to_stats = {}
ip_status = {}
mac_to_port = {}

flowRemovedEventId = None


class SYNFloodBlocker(object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        global flowRemovedEventId
        global mac_to_port
        global ip_to_c
        global ip_to_stats
        global ip_status

        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        self.mac_to_port = mac_to_port
        self.ip_to_c = ip_to_c
        self.ip_to_stats = ip_to_stats
        self.ip_status = ip_status

        if flowRemovedEventId is not None:
            core.openflow.removeListener(flowRemovedEventId)
        flowRemovedEventId = core.openflow.addListenerByName("FlowRemoved", self.handle_flow_removed)

    def handle_flow_removed(self, event):
        """
        Gets called when a temp flow is expired.
        It notes removed flow stats for identifying malicious traffic.
        """

        nw_src = event.ofp.match.nw_src
        packet_count = event.ofp.packet_count
        cookie = event.ofp.cookie
        match = event.ofp.match

        if cookie == 0:
            # temp flow
            self.ip_to_c[str(nw_src)] += 1
            self.ip_to_stats[str(nw_src)] += packet_count
            if self.ip_to_c[str(nw_src)] >= AVG_NUM_OF_CONN:
                s = self.ip_to_stats[str(nw_src)] / self.ip_to_c[str(nw_src)]
                if s > MIN_NUM_OF_PACKETS_PER_CONN:
                    self.install_allow_rule(match)
                    self.ip_status[str(nw_src)] = STATUS_ALLOWED
                else:
                    self.install_drop_rule(nw_src)
                    self.ip_status[str(nw_src)] = STATUS_BLOCKED

                self.ip_to_c[str(nw_src)] = 0
                self.ip_to_stats[str(nw_src)] = 0
        else:
            # removed flow is either an allow or a block entry
            self.ip_status[str(nw_src)] = STATUS_UNKNOWN

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """

        msg = of.ofp_packet_out()
        msg.data = packet_in

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def install_drop_rule(self, nw_src):
        """
        Installs a rule to drop traffic originating from specified src addr.
        """

        nw_src_match = of.ofp_match()
        nw_src_match.dl_type = DL_TYPE_IPV4
        nw_src_match.nw_src = nw_src

        # rules with no action will cause the matching packets to drop
        msg = of.ofp_flow_mod()
        msg.match = nw_src_match
        msg.idle_timeout = EVIL_IDLE_TIMEOUT
        msg.hard_timeout = EVIL_HARD_TIMEOUT
        # Instructs the switch to notify the controller when this flow
        # gets removed
        msg.flags = of.OFPFF_SEND_FLOW_REM
        msg.cookie = hash(str(nw_src)) % (10 ** 8)

        log.debug("Installing a drop rule for %s...", str(nw_src))

        self.connection.send(msg)

    def install_temp_rule(self, packet):
        """
        Installs a temporary rule for unidentified traffic
        """

        srcmac = packet.src
        dstmac = packet.dst
        nw_src = packet.next.srcip
        nw_dst = packet.next.dstip
        port = self.mac_to_port[str(dstmac)]

        temp_match = of.ofp_match()
        temp_match.dl_src = srcmac
        temp_match.dl_dst = dstmac
        temp_match.dl_type = DL_TYPE_IPV4
        temp_match.nw_src = nw_src
        temp_match.nw_dst = nw_dst

        msg = of.ofp_flow_mod()
        msg.match = temp_match
        msg.idle_timeout = TEMP_IDLE_TIMEOUT
        msg.hard_timeout = TEMP_HARD_TIMEOUT
        # Instructs the switch to notify the controller when this flow
        # gets removed
        msg.flags = of.OFPFF_SEND_FLOW_REM

        msg.actions.append(of.ofp_action_output(port=port))

        self.connection.send(msg)

    def install_allow_rule(self, match):
        """
        Installs a temporary rule for unidentified traffic
        """

        dstmac = match.dl_dst
        nw_src = match.nw_src
        nw_dst = match.nw_dst
        port = self.mac_to_port[str(dstmac)]

        msg = of.ofp_flow_mod()
        msg.match = match
        msg.idle_timeout = FREQ_IDLE_TIMEOUT
        msg.hard_timeout = FREQ_HARD_TIMEOUT
        # Instructs the switch to notify the controller when this flow
        # gets removed
        msg.flags = of.OFPFF_SEND_FLOW_REM
        msg.cookie = (hash(str(nw_src)) + hash(str(nw_dst)) + hash(str(port))) % (10 ** 8)

        msg.actions.append(of.ofp_action_output(port=port))

        log.debug("Installing an allow rule for %s->%s...", str(nw_src), str(nw_dst))

        self.connection.send(msg)

    def act_like_switch(self, packet, packet_in):
        """
        Does something similar to a switch
        """

        srcmac = packet.src
        dstmac = packet.dst

        # Learn the port for the source MAC
        self.mac_to_port[str(srcmac)] = packet_in.in_port

        if str(dstmac) in self.mac_to_port:
            if isinstance(packet.next, ipv4) and packet.find('tcp'):
                srcip = str(packet.next.srcip)

                if srcip not in self.ip_to_c:
                    self.ip_to_c[srcip] = 0

                if srcip not in self.ip_to_stats:
                    self.ip_to_stats[srcip] = 0

                status = ip_status.get(srcip, STATUS_UNKNOWN)
                if status == STATUS_UNKNOWN:
                    self.install_temp_rule(packet)

                self.resend_packet(packet_in, self.mac_to_port[str(dstmac)])
            else:
                # Resend non IPV4 packets but don't install a rule
                # (might be bad for performance, but so is implementing
                # a controller with POX)
                self.resend_packet(packet_in, self.mac_to_port[str(dstmac)])
        else:
            # Flood the packet out everything but the input port
            self.resend_packet(packet_in, of.OFPP_ALL)

    # noinspection PyPep8Naming
    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """

        packet = event.parsed  # This is the parsed packet data.

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        self.act_like_switch(packet, packet_in)


def launch():
    def clear_all_flows():
        """
        Clears all flows in all connected switches
        """

        # Create ofp_flow_mod message to delete all flows (note that flow_mods
        # match all flows by default)
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)

        # iterate over all connected switches and delete all their flows
        for connection in core.openflow.connections:
            connection.send(msg)
            log.debug("Cleared all flows from %s..." % dpidToStr(connection.dpid))

    def start_switch(event):
        """
        Starts the component
        """

        log.debug("Controlling %s..." % event.connection)
        clear_all_flows()
        SYNFloodBlocker(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)

    core.Interactive.variables['mac_to_port'] = mac_to_port
    core.Interactive.variables['ip_to_c'] = ip_to_c
    core.Interactive.variables['ip_to_stats'] = ip_to_stats
    core.Interactive.variables['ip_status'] = ip_status
