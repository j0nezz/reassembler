import pandas as pd

__all__ = ['Fingerprint', 'AttackVector']


class Fingerprint:
    def __init__(self, data: dict):
        self.key = data['key']
        self.attack_vectors = [AttackVector(a) for a in data['attack_vectors']]

    def __str__(self):
        return "%s with %d attack vectors" % (self.key, len(self.attack_vectors))


class AttackVector:
    def __init__(self, data: dict):
        self.service = data['service']
        self.protocol = data['protocol']
        self.ttl = TTL(data['ttl'])

    def __str__(self):
        return "Attack Vector %s:%s" % (self.service, self.protocol)


class TTL:
    def __init__(self, ttl_data: dict):
        # Create tuples of (TTL, probability) and remove non-numeric values (e.g. "others)
        self.ttl = [(int(k), v) for k, v in ttl_data.items() if k.isnumeric()]
