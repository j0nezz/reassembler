from fingerprint import Fingerprint

__all__ = ['Reassembler']


class Reassembler:
    def __init__(self, fingerprints: list[Fingerprint]):
        self.fingerprints = fingerprints

    def reassemble(self):
        print("Trying to reassemble %d fingperints..." % len(self.fingerprints))
        for fp in self.fingerprints:
            print(fp)
