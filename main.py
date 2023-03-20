import json

from fingerprint import Fingerprint
from reassembler import Reassembler


def readJSON(path):
    # Opening JSON file
    f = open(path)
    data = json.load(f)
    f.close()
    return data


if __name__ == '__main__':
    router_a = Fingerprint(readJSON('./data/scenario/syn/router-a.json'))
    router_b = Fingerprint(readJSON('./data/scenario/syn/router-b.json'))
    target = Fingerprint(readJSON('./data/scenario/syn/target.json'))
    server_a = Fingerprint(readJSON('./data/scenario/syn/server-a.json'))
    reassembler = Reassembler([router_b, router_a, target, server_a])
    reassembler.reassemble()



