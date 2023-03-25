import json
import os
from pathlib import Path

from fingerprint import Fingerprint
from reassembler import Reassembler
from scenario import create_network, draw_network, generate_attack_fingerprint


def read_fingerprint(path: Path, location: str):
    # Opening JSON file
    f = open(path)
    data = json.load(f)
    f.close()

    # add the capture location to the fingerprint based on the folder structure of the data
    data['location'] = location
    return Fingerprint(data)


if __name__ == '__main__':
    # fingerprints = []
    # for dirpath, dirnames, filenames in os.walk('./data'):
    #     if any(filename.endswith('json') for filename in filenames):
    #         capture_location = dirpath.split(os.sep)[-1]
    #         fingerprints.extend(list(map(lambda p: read_fingerprint(p, capture_location),
    #                                      [Path(dirpath) / filename for filename in filenames])))
    #
    # reassembler = Reassembler(fingerprints)
    # reassembler.reassemble()


    # G = create_network(num_subnets=4, participants_per_subnet=2, num_routers=4, routers_per_layer=2)
    G = create_network(num_subnets=40, participants_per_subnet=2, num_routers=40, routers_per_layer=4)
    draw_network(G)

    sources = ["P1", "P8", "P12", "P30", "P62", "P63", "P64", "P65", "P66"]
    target = "P80"

    fingerprints = generate_attack_fingerprint(G, sources, target)
    output_folder = "fingerprints"
    # Create the output folder if it does not exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for fingerprint in fingerprints:
        output_file = os.path.join(output_folder, f"fingerprint_{fingerprint['location_name']}.json")
        with open(output_file, "w") as f:
            json.dump(fingerprint, f, indent=2)
