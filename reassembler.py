import networkx as nx
import pandas as pd
from matplotlib import pyplot as plt

from fingerprint import Fingerprint

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
        self.av = pd.concat(fp.to_dataframe() for fp in fingerprints)

    def reassemble(self):
        target = self.find_target()
        if target is None:
            raise Exception("No target found")
        target = target.to_dict()
        observing_fp = self.av[
            # TODO: Query by service, but consider that it can be None
            # (self.av['service'] == target['service'][0]) &
            (self.av['protocol'] == target['protocol'][0]) &
            (self.av['target'] == target['target'][0])
            # (self.av['key'] != target['key'][0])
            ].sort_values('ttl', ascending=False)
        plot_connections(observing_fp)
        print(observing_fp[['location', 'protocol', 'ttl']])
        # TODO: Plot connecting line to every node which has TTL -1

    def find_target(self) -> pd.DataFrame:
        """
        Find the overall target of the attack by comparing target and location in each fingerprint
        """
        possible_targets = self.av[self.av['target'] == self.av['location']].sort_values('nr_packets', ascending=False)
        print("Possible Targets: \n", possible_targets[['target', 'location', 'protocol', 'nr_packets']])
        return possible_targets.head(1)


def plot_connections(df: pd.DataFrame):
    g1 = nx.DiGraph()
    edges = [(a['location'], b['location'])
             for (_, a) in df.iterrows()
             for (_, b) in df.iterrows()
             if a['ttl'] > b['ttl']]
    g1.add_edges_from(edges)
    print("is acylcic", nx.is_directed_acyclic_graph(g1))
    nx.draw_networkx(g1, arrows=True, font_size=8)
    plt.show()
