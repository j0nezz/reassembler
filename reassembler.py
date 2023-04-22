import json

import pandas as pd
from pandas import DataFrame

__all__ = ['Reassembler']

from visualization import plot_network


def calculate_hops(ttl_list):
    # Custom function to calculate the number of hops
    common_ttl_values = [32, 64, 128, 255]
    # Find the next higher common TTL value
    # We use >= to account for nodes that record their own sent traffic (random background traffic)
    hops = [min(filter(lambda x: x >= ttl, common_ttl_values)) - ttl for ttl in ttl_list]

    return hops


def calculate_hops_to_target(row):
    ttl = row['ttl']
    ttl_on_target = row['ttl_on_target']

    distances = []

    for t in ttl:
        # Get the largest ttl_on_target value that is smaller than t
        valid_targets = [x for x in ttl_on_target if x <= t]
        if valid_targets:
            target = max(valid_targets)
            distance = t - target
        else:
            distance = float('inf')
        distances.append(distance)

    # Calculate the mean distance
    mean_distance = sum(distances) / len(distances)
    return mean_distance


class Reassembler:
    def __init__(self, fingerprints: DataFrame):
        self.fps = fingerprints

    def reassemble(self):
        target, target_key = self.find_target()

        entries_at_target = self.fps[(self.fps['location'] == target) & (self.fps['target'] == target)].copy()
        entries_at_target['ttl_count'] = entries_at_target['ttl'].apply(lambda x: len(x))
        entries_at_target['time_start'] = pd.to_datetime(entries_at_target['time_start'])
        entries_at_target['time_end'] = entries_at_target['time_start'] + pd.to_timedelta(entries_at_target['duration_seconds'], unit='s')
        total_attack_size_at_target = entries_at_target['nr_packets'].sum()
        print("Entries at Target", entries_at_target[['source_ip', 'nr_packets', 'target', 'location']])

        ttls_at_target = entries_at_target[['source_ip', 'ttl']].copy()
        ttls_at_target.columns = ['source_ip', 'ttl_on_target']
        ttls_at_target['hops_on_target'] = ttls_at_target['ttl_on_target'].apply(calculate_hops)

        observing_fp = self.fps[(self.fps['target'] == target) & (self.fps['location'] != target)].copy()
        observing_fp['hops'] = observing_fp['ttl'].apply(calculate_hops)
        observing_fp = observing_fp.merge(ttls_at_target, how='left', on='source_ip')
        observing_fp['hops_to_target'] = observing_fp.apply(calculate_hops_to_target, axis=1)
        print(observing_fp[['location', 'source_ip', 'ttl', 'detection_threshold']].sort_values(
            'location'))

        sources = entries_at_target['ttl'].apply(lambda x: len(x))

        intermediate_nodes = observing_fp.groupby('location').agg({'nr_packets': 'sum', 'hops_to_target': 'mean', 'detection_threshold':'min'})
        intermediate_nodes['hops_to_target'] = intermediate_nodes['hops_to_target'].round()
        intermediate_nodes['fraction_of_total_attack'] = intermediate_nodes['nr_packets'] / total_attack_size_at_target
        bins = intermediate_nodes.groupby('hops_to_target')['nr_packets'].apply(list)

        plot_network(sources.tolist(), bins.sort_index(ascending=False).tolist())

        pct_spoofed = len(entries_at_target[entries_at_target['ttl_count'] > 1]) / len(entries_at_target)
        summary = {
            'attack': {
                'start_time': entries_at_target['time_start'].min().isoformat(),
                'end_time': entries_at_target['time_end'].max().isoformat()
            },
            'target': {
                'ip': target
            },
            'intermediate_nodes': {
                'nr_intermediate_nodes': len(intermediate_nodes),
                'key_nodes': intermediate_nodes.sort_values('nr_packets', ascending=False).head(20).sort_values('hops_to_target').to_dict('index')
            },
            'sources': {
                'nr_sources': len(sources),
                'pct_spoofed': pct_spoofed
            }
        }
        self.save_to_json(summary, 'summary.json')

    def find_target(self) -> tuple[str, str]:
        """
        Find the overall target of the attack by comparing target and location in each fingerprint
        """
        # TODO: Possibly Better detection or manual way to define target
        possible_targets = self.fps[self.fps['target'] == self.fps['location']].groupby(['location', 'target']).agg(
            {'nr_packets': 'sum', 'key': 'min'}).sort_values('nr_packets', ascending=False)

        return possible_targets.index[0][0], possible_targets.iloc[0]['key']

    def save_to_json(self, data, filename='data.json'):
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
