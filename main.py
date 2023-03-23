import json
import os
from pathlib import Path

from fingerprint import Fingerprint
from reassembler import Reassembler


def read_fingerprint(path: Path, location: str):
    # Opening JSON file
    f = open(path)
    data = json.load(f)
    f.close()

    # add the capture location to the fingerprint based on the folder structure of the data
    data['location'] = location
    return Fingerprint(data)


if __name__ == '__main__':
    fingerprints = []
    for dirpath, dirnames, filenames in os.walk('./data'):
        if any(filename.endswith('json') for filename in filenames):
            capture_location = dirpath.split(os.sep)[-1]
            fingerprints.extend(list(map(lambda p: read_fingerprint(p, capture_location),
                                         [Path(dirpath) / filename for filename in filenames])))

    reassembler = Reassembler(fingerprints)
    reassembler.reassemble()
