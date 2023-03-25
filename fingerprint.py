from functools import reduce

import pandas as pd

__all__ = ['Fingerprint', 'AttackVector']


class Fingerprint:
    def __init__(self, data: dict):
        self.key = data['key']
        # TODO: Change to IPNetwork type
        self.location: str = data['location']
        self.target: str = data['target']
        self.attack_vectors = [AttackVector(a) for a in data['attack_vectors']]

    def to_dataframe(self):
        df = pd.concat(pd.DataFrame(
            {'service': [av.service], 'protocol': [av.protocol], 'duration_seconds': [av.duration_seconds],
             'time_start': [av.time_start], 'nr_packets': [av.nr_packets], 'target': self.target,
             'location': self.location, 'key': self.key, 'ttl': av.ttl.mean()}) for av in self.attack_vectors)
        df["time_start"] = pd.to_datetime(df["time_start"])
        return df

    def __str__(self):
        return "%s with %d attack vectors" % (self.key, len(self.attack_vectors))


class AttackVector:
    def __init__(self, data: dict):
        self.service = data['service']
        self.protocol = data['protocol']
        self.ttl = TTL(data['ttl'])
        self.duration_seconds = data['duration_seconds']
        self.nr_packets = data['nr_packets']
        self.time_start = data['time_start']

    def __str__(self):
        return "Attack Vector %s:%s" % (self.service, self.protocol)


class TTL:
    def __init__(self, ttl_data: dict):
        # Create tuples of (TTL, probability) and remove non-numeric values (e.g. "others)
        self.ttl = [(int(k), v) for k, v in ttl_data.items() if k.isnumeric()]

    def mean(self):
        p_sum = sum(n for _, n in self.ttl)
        # Probabilities might not always add up to 1 => normalize with p_sum
        return sum(t * (p/p_sum) for t, p in self.ttl)

