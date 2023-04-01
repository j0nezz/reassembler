import json
import os
from pathlib import Path

from fingerprint import Fingerprint
from reassembler import Reassembler
from scenario import create_network, draw_network, generate_attack_fingerprint


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
    G = create_network(num_subnets=40, participants_per_subnet=4, routers_per_layer=5)
    draw_network(G)

    sources = ["P1", "P5", "P26"]
    target = "P30"

    fingerprints = generate_attack_fingerprint(G, sources, target, num_background_fp=10)
    output_folder = "fingerprints"
    # Create the output folder if it does not exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for fingerprint in fingerprints:
        output_file = os.path.join(output_folder, f"{fingerprint['location_name']}_{fingerprint['target_name']}.json")
        with open(output_file, "w") as f:
            json.dump(fingerprint, f, indent=2)

    reassemble_folder('./fingerprints')
