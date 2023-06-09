import json
import os

import numpy as np
import pandas as pd
from matplotlib import pyplot as plt

from utils import calculate_hash
from .fingerprint import flatten_fingerprint, read_fingerprints_from_folder

__all__ = ['Reassembler']

DEFAULT_PERCENTILES = [25, 50, 75]


class Reassembler:
    def __init__(self, fingerprint_folder=None, fingerprint_data=None, simulated=True):
        # Avoid mutable default value
        if fingerprint_data is None:
            fingerprint_data = []

        if len(fingerprint_data) > 0:
            self.fps = pd.concat([pd.json_normalize(flatten_fingerprint(x, simulated=simulated), 'attack_vectors')
                                  for x in fingerprint_data], ignore_index=True)
        elif fingerprint_folder is not None:
            self.fps = read_fingerprints_from_folder(fingerprint_folder, simulated=simulated)
        else:
            raise ValueError("No Fingerprint Data provided")

        self.fps['time_start'] = pd.to_datetime(self.fps['time_start'])
        self.fps['time_end'] = self.fps['time_start'] + pd.to_timedelta(self.fps['duration_seconds'], unit='s')
        self.target = self.find_target()
        self.drop = 0
        self.simulated = simulated
        self.summary = None

    def drop_fingerprints(self, percentage_to_drop):
        self.drop = percentage_to_drop

        if percentage_to_drop > 0:
            unique_keys = self.fps[self.fps['location'] != self.target]['key'].unique()
            num_to_drop = int(len(unique_keys) * percentage_to_drop)
            keys_to_drop = np.random.choice(unique_keys, num_to_drop, replace=False)
            rows_to_drop = self.fps[self.fps['key'].isin(keys_to_drop)].index
            df_dropped = self.fps.drop(rows_to_drop)
            self.fps = df_dropped.copy()

        return self

    def draw_percentiles(self, df, colA, colB, percentiles=None):
        if percentiles is None:
            percentiles = DEFAULT_PERCENTILES

        colormap = plt.get_cmap('tab10')

        percentile_values = calculate_percentile_values(df[colB], percentiles)
        categories = pd.cut(df[colB], bins=[-np.inf, *percentile_values, np.inf], labels=False, duplicates="drop")

        # Calculate the minimum and maximum values of the column
        min_value = df['nr_packets'].min()
        max_value = df['nr_packets'].max()

        # Perform min-max scaling
        df['sizes'] = (df['nr_packets'] - min_value) / (max_value - min_value)

        # Create the scatter plot with the assigned colors
        plt.scatter(df[colA], df[colB], c=colormap(categories), s=df['sizes'] * 200)

        # Draw percentile lines and add legend
        for value, percentile, color in zip(percentile_values, percentiles, colormap.colors[:-1]):
            plt.axhline(value, linestyle='--', color=color, label=f'{percentile}th percentile')

        plt.xlabel("Hops to Target")
        plt.ylabel("Detection Threshold")
        plt.legend(loc='upper right')
        plt.tight_layout()
        plt.show()

        return self

    def plot_attack_coverage(self, data):
        plt.rc('font', size=15)
        plt.bar(data['hops_to_target'], data['fraction_of_total_attack'])
        plt.ylim(0, 1)
        threshold = 1
        tolerance = 1e-6
        for i, value in enumerate(data['fraction_of_total_attack']):
            if value - tolerance > threshold:
                plt.gca().get_children()[i].set_color('tab:red')

        plt.xlabel("Distance to Target (Hops)")
        plt.ylabel("Fraction of Total Attack")
        plt.tight_layout()
        plt.savefig(f"coverage-dropped-{self.drop:.1f}.png", dpi=300)
        plt.show()

    def reassemble(self, draw_percentiles=False, plot_coverage=False):
        target = self.target

        # Select Values at Target
        entries_at_target = self.fps[(self.fps['location'] == target) & (self.fps['target'] == target)].copy()
        entries_at_target['ttl_count'] = entries_at_target['ttl'].apply(lambda x: len(x))
        total_nr_packets_at_target = entries_at_target['nr_packets'].sum()
        # incoming ttl + derive hops from attack target perspective
        ttls_at_target = entries_at_target[
            ['source_ip', 'ttl']].copy()
        ttls_at_target.columns = ['source_ip', 'ttl_on_target']
        ttls_at_target['hops_on_target'] = ttls_at_target['ttl_on_target'].apply(calculate_hops)

        # Find Intermediate Nodes
        observing_fp = self.fps[(self.fps['target'] == target) &
                                (self.fps['location'] != target)].copy()
        # Merge the TTL observed at the target for further aggregation
        observing_fp = observing_fp.merge(ttls_at_target, how='left', on='source_ip')
        observing_fp['hops_to_target'] = observing_fp.apply(calculate_hops_to_target, axis=1)
        # Aggregate intermediate nodes
        agg_config = {'nr_packets': 'sum', 'hops_to_target': 'mean', 'detection_threshold': 'min', 'time_start': 'min',
                      'time_end': 'max'}
        if self.simulated:
            agg_config['distance'] = 'min'

        intermediate_nodes = observing_fp.groupby('location').agg(agg_config).copy()
        intermediate_nodes['hops_to_target'] = intermediate_nodes['hops_to_target'].round()

        if self.simulated:
            intermediate_nodes['inferred_distance_diff'] = (
                    intermediate_nodes['hops_to_target'] - intermediate_nodes['distance'])

        intermediate_nodes['fraction_of_total_attack'] = intermediate_nodes['nr_packets'] / total_nr_packets_at_target
        intermediate_nodes['duration_seconds'] = (
                intermediate_nodes['time_end'] - intermediate_nodes['time_start']).dt.total_seconds()
        intermediate_nodes = intermediate_nodes.applymap(lambda x: x.isoformat() if isinstance(x, pd.Timestamp) else x)

        # Discard background intermediate nodes based on a time threshold
        filtered_intermediate_nodes = intermediate_nodes[intermediate_nodes['duration_seconds'] > 60]

        pct_spoofed = len(entries_at_target[entries_at_target['ttl_count'] > 1]) / len(entries_at_target)

        threshold_percentiles = calculate_percentile_values(filtered_intermediate_nodes['detection_threshold'],
                                                            DEFAULT_PERCENTILES)

        summary = {
            'attack': {
                'start_time': entries_at_target['time_start'].min().isoformat(),
                'end_time': entries_at_target['time_end'].max().isoformat(),
                'duration_seconds': entries_at_target['duration_seconds'].mean(),
                'service': entries_at_target['service'].value_counts().idxmax() if entries_at_target['service'].notna().any() else None,
                'protocol': entries_at_target['protocol'].value_counts().idxmax()
            },
            'target': {
                'ip': target,
                'detection_threshold': entries_at_target['detection_threshold'].mean()
            },
            'intermediate_nodes': {
                'discarded_intermediate_nodes': len(intermediate_nodes) - len(filtered_intermediate_nodes),
                'nr_intermediate_nodes': len(filtered_intermediate_nodes),
                'detection_threshold': {p: v for p, v in zip(DEFAULT_PERCENTILES, threshold_percentiles)},
                'key_nodes': filtered_intermediate_nodes.sort_values('nr_packets', ascending=False).sort_values(
                    'hops_to_target').to_dict('index')
            },
            'sources': {
                'nr_sources': len(entries_at_target),
                'pct_spoofed': pct_spoofed
            }
        }

        self.summary = summary

        if plot_coverage:
            grouped_data = filtered_intermediate_nodes.groupby('hops_to_target')[
                'fraction_of_total_attack'].sum().reset_index()
            self.plot_attack_coverage(grouped_data)

        if draw_percentiles:
            self.draw_percentiles(filtered_intermediate_nodes, 'hops_to_target', 'detection_threshold')

        return self

    def add_ground_truth_data(self, target, sources):
        if self.summary is None:
            raise ValueError("Please call the reassemble method first")

        nr_attack_av = len(self.fps[self.fps['is_attack']])
        nr_background_av = len(self.fps[~self.fps['is_attack']])
        nr_participating_nodes = self.fps['location'].nunique()
        locations = self.fps[self.fps['location'] != self.target].groupby('location').agg({'is_attack': 'any'})
        nr_locations_observing_attack = len(locations[locations['is_attack']])

        ground_truth = {
            'nr_attack_av': nr_attack_av,
            'nr_background_av': nr_background_av,
            'nr_participating_nodes': nr_participating_nodes,
            'nr_locations_observing_attack': nr_locations_observing_attack,
            'sources': list(map(str, sources)),
            'target': str(target)
        }

        self.summary['ground_truth'] = ground_truth

        return self

    def find_target(self) -> str:
        possible_targets = (self.fps[(self.fps['target'] == self.fps['location']) &
                                     (self.fps['detection_threshold'] >= 0.5)]
                            .groupby(['location'])
                            .agg({'nr_packets': 'sum', 'key': 'min', 'detection_threshold': 'min'})
                            .sort_values('nr_packets', ascending=False))

        if len(possible_targets) == 0:
            raise ValueError("No Target found with the desired attack threshold")

        # returns IP of most targeted location
        return possible_targets.index[0]

    def save_to_json(self, base_dir="./global-fp"):
        if self.summary is None:
            raise ValueError("Please call the reassemble method first")

        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        data = calculate_hash(self.summary)

        with open(f"{base_dir}/{data['key']}.json", "w") as f:
            json.dump(data, f, indent=2)

        return self


# Helper Methods

def calculate_hops(ttl_list):
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


def calculate_percentile_values(df_col, percentiles=None):
    if percentiles is None:
        percentiles = DEFAULT_PERCENTILES
    return [np.percentile(df_col, p) for p in percentiles]
