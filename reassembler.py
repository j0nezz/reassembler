from fingerprint import Fingerprint
from netaddr import IPNetwork

__all__ = ['Reassembler']


class Reassembler:
    def __init__(self, fingerprints: list[Fingerprint]):
        self.fingerprints = fingerprints

        fp_by_loc: dict[str, list[Fingerprint]] = {}
        for fp in fingerprints:
            if fp.location in fp_by_loc:
                fp_by_loc[fp.location].append(fp)
            else:
                fp_by_loc[fp.location] = [fp]
        self.fingerprints_by_location = fp_by_loc

    def reassemble(self):
        print("Trying to reassemble %d fingperints..." % len(self.fingerprints))
        print(self.fingerprints_by_location)

    def find_target(self) -> IPNetwork:
        """
        Find the overall target of the attack by comparing target and location in each fingerprint
        """
        for fp in self.fingerprints:
            if fp.location == fp.target:
                print("Target found", fp.location)
                return IPNetwork(fp.location)

