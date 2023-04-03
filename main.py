import json
import os
import random
from pathlib import Path

from netaddr import IPNetwork

from fingerprint import Fingerprint
from reassembler import Reassembler
from scenario import create_network, draw_network, generate_attack_fingerprint

random.seed(12)

def read_fingerprint(path: Path, location=""):
    # Opening JSON file
    f = open(path)
    data = json.load(f)
    f.close()
    if location != "":
        data['location'] = location

    # add the capture location to the fingerprint based on the folder structure of the data
    return Fingerprint(data)


def reassemble_folder(path, infer_location_from_folder_structure=False):
    fingerprints = []
    for dirpath, dirnames, filenames in os.walk(path):
        if any(filename.endswith('json') for filename in filenames):
            if infer_location_from_folder_structure:
                capture_location = dirpath.split(os.sep)[-1]
                fingerprints.extend(list(map(lambda p: read_fingerprint(p, capture_location),
                                             [Path(dirpath) / filename for filename in filenames])))
            else:
                fingerprints.extend(list(map(lambda p: read_fingerprint(p),
                                             [Path(dirpath) / filename for filename in filenames])))

    reassembler = Reassembler(fingerprints)
    reassembler.reassemble()


if __name__ == '__main__':
    #  IPNetwork("72.0.0.0/8"),  IPNetwork("71.220.0.0/16")
    G = create_network([IPNetwork("10.0.0.0/16")], max_clients=2)
    draw_network(G)

    clients = [n for n, data in G.nodes(data=True) if data['client']]
    sources = random.sample(clients, 1)
    possible_targets = [n for n, data in G.nodes(data=True) if data['client'] and not data.get('spoofed', False) and not n in sources]
    target = random.choice(possible_targets)

    print("Creating scenario with sources \n", [G.nodes(data=True)[s].get('spoofed_ip', s) for s in sources], "\n and target", target)

    fingerprints = generate_attack_fingerprint(G, sources, target, num_background_fp=0)
    output_folder = "fingerprints"
    # Create the output folder if it does not exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for fingerprint in fingerprints:
        output_file = os.path.join(output_folder, f"{fingerprint['location']}_{fingerprint['target']}.json")
        with open(output_file, "w") as f:
            json.dump(fingerprint, f, indent=2)

    reassemble_folder('./fingerprints')
