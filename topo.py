#!/usr/bin/python

# The following is based on the code generated by miniedit tool

from os import path

from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.node import RemoteController


def get_path(file_name):
    script_dir = path.dirname(path.realpath(__file__))
    return path.join(script_dir, file_name)


def run_web_server(host):
    web_server_script_path = get_path("webserver.py")
    web_server_log_path = get_path("webserver.log")
    cmd = "python %s &> %s &" % (web_server_script_path, web_server_log_path)
    host.cmd(cmd)


def run_frequent_user(host, server):
    frequent_script_path = get_path("frequent.py")
    cmd = "python %s %s:8080 &" % (frequent_script_path, server.IP())
    host.cmd(cmd)


def run_malicious_user(host):
    synflood_script_path = get_path("synflood.py")
    cmd = "python %s &" % synflood_script_path
    host.cmd(cmd)


def run_syn_flooder(host, server):
    synflood_script_path = get_path("synflood.py")
    cmd = "python %s %s &" % (synflood_script_path, server.IP())
    host.cmd(cmd)


def my_network():
    net = Mininet(topo=None,
                  build=False,
                  ipBase="10.0.0.0/8")

    info("*** Adding controller\n")
    c0 = net.addController(name="c0",
                           controller=RemoteController,
                           protocol="tcp",
                           port=6633)

    info("*** Add switches\n")
    s1 = net.addSwitch("s1", cls=OVSKernelSwitch)

    info("*** Add hosts\n")
    h1 = net.addHost("h1", cls=Host, ip="10.0.0.1", defaultRoute=None)
    h2 = net.addHost("h2", cls=Host, ip="10.0.0.2", defaultRoute=None)
    h3 = net.addHost("h3", cls=Host, ip="10.0.0.3", defaultRoute=None)
    h4 = net.addHost("h4", cls=Host, ip="10.0.0.4", defaultRoute=None)

    info("*** Add links\n")
    net.addLink(s1, h1)
    net.addLink(s1, h2)
    net.addLink(s1, h3)
    net.addLink(s1, h4)

    info("*** Starting network\n")
    net.build()
    info("*** Starting controllers\n")
    for controller in net.controllers:
        controller.start()

    info("*** Starting switches\n")
    net.get("s1").start([c0])

    info("*** Post configure switches and hosts\n")

    run_web_server(h4)
    run_frequent_user(h2, h4)
    run_malicious_user(h1)
    run_syn_flooder(h3, h4)

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    my_network()
