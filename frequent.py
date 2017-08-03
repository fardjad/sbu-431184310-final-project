#!/usr/bin/python

import httplib
import sys
from time import sleep

# constants
FLOW_TIMEOUT = 30
N = 10  # just to make sure it sends enough packets to be identified as a frequent users
MAX_REQUESTS = 10

count = 0


def req(url):
    conn = httplib.HTTPConnection(url, timeout=5)
    for f in range(N):
        conn.request("GET", "/%s/%s" % (str(count), f + 1))
        r1 = conn.getresponse()
        r1.read()
    conn.close()
    sleep(0.01)


def start(url):
    global count

    print("Frequent user simulation started.")

    while count < MAX_REQUESTS:
        count += 1
        try:
            req(url)
        except Exception as ex:
            print(ex)
        sleep(FLOW_TIMEOUT)

    print("Frequent user simulation finished.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: " + __file__ + " <DST_IP:PORT>")
    else:
        start(sys.argv[1])
