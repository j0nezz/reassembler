import networkx as nx
import pandas as pd
from matplotlib import pyplot as plt
from pandas import DataFrame

__all__ = ['Reassembler']

from visualization import plot_network


def calculate_hops(ttl):
    # Custom function to calculate the number of hops
    common_ttl_values = [32, 64, 128, 255]
    # Find the next higher common TTL value
    next_higher_ttl = min(filter(lambda x: x > ttl, common_ttl_values))

    # Calculate the number of hops
    hops = next_higher_ttl - ttl
    return hops


class Reassembler:
    def __init__(self, fingerprints: DataFrame):
        self.fps = fingerprints

    def reassemble(self):
        target, target_key = self.find_target()

        ttls_at_target = self.fps[self.fps['location'] == target][['source_ip', 'ttl']]
        ttls_at_target.columns = ['source_ip', 'ttl_on_target']
        observing_fp = self.fps[self.fps['target'] == target]
        observing_fp['hops'] = observing_fp['ttl'].apply(calculate_hops)
        observing_fp = observing_fp.merge(ttls_at_target, how='left', on='source_ip')
        observing_fp['distance_to_target'] = observing_fp['ttl'] - observing_fp['ttl_on_target']
        print(observing_fp[['location', 'source_ip', 'ttl', 'ttl_on_target', 'distance_to_target']].sort_values(
            'distance_to_target'))
        # print("Observing FP", observing_fp[['location', 'source_ip', 'ttl', 'hops', 'nr_packets']].sort_values('hops', ascending=False))
        # print("Reassemble", observing_fp.groupby('location').agg({'nr_packets': 'sum', 'ttl':'mean'}))

        sources = observing_fp['source_ip'].unique()
        intermediate_nodes = observing_fp.groupby('location').agg({'nr_packets': 'sum', 'distance_to_target': 'mean'})
        bins = intermediate_nodes.groupby('distance_to_target')['nr_packets'].apply(list)
        # print("Bins", type(bins), bins)
        plot_network([1 for _ in sources], bins.sort_index(ascending=False).tolist())

    def find_target(self) -> tuple[str, str]:
        """
        Find the overall target of the attack by comparing target and location in each fingerprint
        """
        possible_targets = self.fps[self.fps['target'] == self.fps['location']].groupby(['location', 'target']).agg(
            {'nr_packets': 'sum', 'key': 'min'}).sort_values('nr_packets', ascending=False)

        return possible_targets.index[0][0], possible_targets.iloc[0]['key']


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
