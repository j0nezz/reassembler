import json
import os

import numpy as np
import pandas as pd
from matplotlib import pyplot as plt

from utils import calculate_hash
from .fingerprint import flatten_fingerprint, read_fingerprints_from_folder

__all__ = ['Reassembler']

DEFAULT_PERCENTILES = [25, 50, 75]


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
    # mean_distance = np.mean(ttl) - np.mean(ttl_on_target)
    mean_distance = sum(distances) / len(distances)
    return mean_distance


def calculate_percentile_values(df_col, percentiles=None):
    if percentiles is None:
        percentiles = DEFAULT_PERCENTILES
    return [np.percentile(df_col, p) for p in percentiles]


class Reassembler:
    def __init__(self, fingerprint_folder=None, fingerprint_data=[]):

        if len(fingerprint_data) > 0:
            self.fps = pd.concat([pd.json_normalize(flatten_fingerprint(x), 'attack_vectors')
                                  for x in fingerprint_data], ignore_index=True)
        elif fingerprint_folder is not None:
            self.fps = read_fingerprints_from_folder(fingerprint_folder)
        else:
            raise ValueError("No Fingerprint Data provided")

        self.fps['time_start'] = pd.to_datetime(self.fps['time_start'])
        self.fps['time_end'] = self.fps['time_start'] + pd.to_timedelta(self.fps['duration_seconds'], unit='s')
        self.target = self.find_target()

    def drop_fingerprints(self, percentage_to_drop):
        num_rows_to_drop = int(self.fps.shape[0] * percentage_to_drop)
        rows_to_drop = self.fps[self.fps['location'] != self.target].sample(n=num_rows_to_drop).index
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
        plt.legend()
        plt.tight_layout()
        plt.show()

        return self

    def reassemble(self):
        target = self.target

        # TODO: Include protocol / service
        entries_at_target = self.fps[(self.fps['location'] == target) & (self.fps['target'] == target)].copy()
        entries_at_target['ttl_count'] = entries_at_target['ttl'].apply(lambda x: len(x))
        total_attack_size_at_target = entries_at_target['nr_packets'].sum()

        # incoming ttl + derive hops from attack target perspective
        ttls_at_target = entries_at_target[
            ['source_ip', 'ttl']].copy()  # TODO => For multiple attack vectors, there might be multiple entries per IP
        ttls_at_target.columns = ['source_ip', 'ttl_on_target']
        ttls_at_target['hops_on_target'] = ttls_at_target['ttl_on_target'].apply(calculate_hops)

        observing_fp = self.fps[(self.fps['target'] == target) &
                                (self.fps['location'] != target)
            # Filter fingerprints from attack sources to prevent adversarial attacks
            # & ~self.fps['location'].isin(entries_at_target['source_ip'])
                                ].copy()

        # Filtering by attak source poses the problem, that intermediate nodes are not considered if they send a legitimate own packet to the target
        # In turn, this could also be abused to intentionally cancel out intermediate nodes by spoofing their IP address and sending a packet.
        # print("Filter by attack source: ",
        #      len(observing_fp[observing_fp['location'].isin(entries_at_target['source_ip'])]))
        observing_fp = observing_fp.merge(ttls_at_target, how='left', on='source_ip')
        observing_fp['hops_to_target'] = observing_fp.apply(calculate_hops_to_target, axis=1)

        sources = entries_at_target['ttl'].apply(lambda x: len(x))

        # TODO: Filter out fingerprints from sources
        intermediate_nodes = observing_fp.groupby('location').agg(
            {'nr_packets': 'sum', 'hops_to_target': 'mean', 'detection_threshold': 'min', 'time_start': 'min',
             'time_end': 'max', 'distance': 'min'}).copy()
        intermediate_nodes['hops_to_target'] = intermediate_nodes['hops_to_target'].round()
        intermediate_nodes['inferred_distance_diff'] = (
                intermediate_nodes['hops_to_target'] - intermediate_nodes['distance'])
        intermediate_nodes['fraction_of_total_attack'] = intermediate_nodes['nr_packets'] / total_attack_size_at_target
        intermediate_nodes['duration_seconds'] = (
                intermediate_nodes['time_end'] - intermediate_nodes['time_start']).dt.total_seconds()
        intermediate_nodes = intermediate_nodes.applymap(lambda x: x.isoformat() if isinstance(x, pd.Timestamp) else x)

        # TODO make this threshold dynamic based on observed values at the target (e.g. <1% of attack duration)
        #    print("Z-Score", np.abs(stats.zscore(intermediate_nodes['duration_seconds'])))
        # filtered_intermediate_nodes = intermediate_nodes[np.abs(stats.zscore(intermediate_nodes['duration_seconds'])) < 3]
        filtered_intermediate_nodes = intermediate_nodes[intermediate_nodes['duration_seconds'] > 60]

        pct_spoofed = len(entries_at_target[entries_at_target['ttl_count'] > 1]) / len(entries_at_target)

        threshold_percentiles = calculate_percentile_values(filtered_intermediate_nodes['detection_threshold'],
                                                            DEFAULT_PERCENTILES)

        summary = {
            'attack': {
                'start_time': entries_at_target['time_start'].min().isoformat(),
                'end_time': entries_at_target['time_end'].max().isoformat(),
                'duration_seconds': entries_at_target['duration_seconds'].mean()
            },
            'target': {
                'ip': target
            },
            'intermediate_nodes': {
                'discarded_intermediate_nodes': len(intermediate_nodes) - len(filtered_intermediate_nodes),
                'nr_intermediate_nodes': len(filtered_intermediate_nodes),
                'detection_threshold': {p: v for p, v in zip(DEFAULT_PERCENTILES, threshold_percentiles)},
                'key_nodes': filtered_intermediate_nodes.sort_values('nr_packets', ascending=False).sort_values(
                    'hops_to_target').to_dict('index')
            },
            'sources': {
                'nr_sources': len(sources),
                'pct_spoofed': pct_spoofed
            }
        }

        self.summary = summary

        # filtered_intermediate_nodes.plot.scatter(x='hops_to_target', y='fraction_of_total_attack')
        grouped_data = filtered_intermediate_nodes.groupby('hops_to_target')[
            'fraction_of_total_attack'].sum().reset_index()

        # grouped_data.plot.bar(x='hops_to_target', y='fraction_of_total_attack')
        # print(filtered_intermediate_nodes.columns)
        # self.draw_percentiles(filtered_intermediate_nodes, 'hops_to_target', 'detection_threshold')

        return self

        # self.draw_percentiles(filtered_intermediate_nodes, 'hops_to_target', 'detection_threshold')
        # sns.lmplot(x='hops_to_target', y='detection_threshold', data=filtered_intermediate_nodes, fit_reg=True)

        # filtered_intermediate_nodes.plot.scatter(x='hops_to_target', y='detection_threshold')

        # bins = filtered_intermediate_nodes.groupby('hops_to_target').agg(
        #    {'nr_packets': list, 'fraction_of_total_attack': 'sum'})

        # plot_network(sources.tolist(), bins['nr_packets'].sort_index(ascending=False).tolist())

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
        """
        Find the overall target of the attack by comparing target and location in each fingerprint
        """
        possible_targets = (self.fps[(self.fps['target'] == self.fps['location']) &
                                     (self.fps['detection_threshold'] > 0.5)]
                            .groupby(['location'])
                            .agg({'nr_packets': 'sum', 'key': 'min', 'detection_threshold': 'min'})
                            .sort_values('nr_packets', ascending=False))

        if len(possible_targets) == 0:
            raise ValueError("No Target found with the desired attack threshold")

        # returns IP of most targeted location
        return possible_targets.index[0]

    def save_to_json(self, baseDir="./global-fp"):
        print("Saving...")
        if self.summary is None:
            raise ValueError("Please call the reassemble method first")

        if not os.path.exists(baseDir):
            os.makedirs(baseDir)

        data = calculate_hash(self.summary)

        with open(f"{baseDir}/{data['key']}.json", "w") as f:
            json.dump(data, f, indent=2)

        return self
