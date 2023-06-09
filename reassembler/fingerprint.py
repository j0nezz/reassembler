import json
import os

import pandas as pd

__all__ = ['flatten_fingerprint', 'read_fingerprints_from_folder']


def flatten_fingerprint(data, simulated=False):
    """
    Extract nested data and create new records with the desired format
    :param data: List of attack vectors that make up the attack
    :param simulated: Boolean stating whether additional values from the simulation are availble (is_attack, distance)
    :return: Dictionary with flattened list of attack vectors
    """
    new_attack_vectors = []

    for av in data['attack_vectors']:
        for src_ip in av['source_ips']:
            new_attack_vector = {
                'key': data['key'],
                'source_ip': src_ip,
                'ttl': av['ttl_by_source'][src_ip],
                'nr_packets': av['nr_packets_by_source'][src_ip],
                **{k: av[k] for k in ['service', 'protocol', 'duration_seconds', 'time_start', 'detection_threshold']},
                **{k: data[k] for k in ['target', 'location']}
            }
            if simulated:
                new_attack_vector['distance'] = data['distance']
                new_attack_vector['is_attack'] = av['is_attack']
                new_attack_vector['source_ip_real'] = av['source_ips_real'][src_ip]
            new_attack_vectors.append(new_attack_vector)

    data['attack_vectors'] = new_attack_vectors
    return data


def read_fingerprints_from_folder(path: str, simulated=False) -> pd.DataFrame:
    """
    Read fingerprints from a folder into a DataFrame
    :param path: Path of folder where fingerprints are located
    :param simulated: Boolean stating whether additional values from the simulation are availble (is_attack, distance)
    :return: Dataframe of flattened fingerprints
    """
    # create an empty list to store the DataFrames
    dfs = []

    # loop over each JSON file in the folder
    for filename in os.listdir(path):
        if filename.endswith('.json'):
            with open(os.path.join(path, filename)) as f:
                # load the JSON data into a Python dictionary
                data = json.load(f)
                reformatted_data = flatten_fingerprint(data, simulated=simulated)
                df = pd.json_normalize(reformatted_data, 'attack_vectors')
                dfs.append(df)

    return pd.concat(dfs, ignore_index=True)
