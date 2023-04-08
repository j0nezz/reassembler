from pandas import DataFrame

__all__ = ['Reassembler']

from visualization import plot_network


def calculate_hops(ttl_list):
    # Custom function to calculate the number of hops
    common_ttl_values = [32, 64, 128, 255]
    # Find the next higher common TTL value
    hops = [min(filter(lambda x: x > ttl, common_ttl_values)) - ttl for ttl in ttl_list]

    return hops


def calculate_distance_to_target(row):
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

        entries_at_target = self.fps[self.fps['location'] == target]
        ttls_at_target = entries_at_target[['source_ip', 'ttl']]
        ttls_at_target.columns = ['source_ip', 'ttl_on_target']
        ttls_at_target['hops_on_target'] = ttls_at_target['ttl_on_target'].apply(calculate_hops)

        observing_fp = self.fps[self.fps['target'] == target]
        observing_fp['hops'] = observing_fp['ttl'].apply(calculate_hops)
        observing_fp = observing_fp.merge(ttls_at_target, how='left', on='source_ip')
        observing_fp['distance_to_target'] = observing_fp.apply(calculate_distance_to_target, axis=1)
        print(observing_fp[['location', 'source_ip', 'ttl', 'ttl_on_target', 'distance_to_target']].sort_values(
            'distance_to_target'))

        sources = entries_at_target['ttl'].apply(lambda x: len(x))
        intermediate_nodes = observing_fp.groupby('location').agg({'nr_packets': 'sum', 'distance_to_target': 'mean'})
        bins = intermediate_nodes.groupby('distance_to_target')['nr_packets'].apply(list)

        plot_network(sources.tolist(), bins.sort_index(ascending=False).tolist())

    def find_target(self) -> tuple[str, str]:
        """
        Find the overall target of the attack by comparing target and location in each fingerprint
        """
        possible_targets = self.fps[self.fps['target'] == self.fps['location']].groupby(['location', 'target']).agg(
            {'nr_packets': 'sum', 'key': 'min'}).sort_values('nr_packets', ascending=False)

        return possible_targets.index[0][0], possible_targets.iloc[0]['key']
