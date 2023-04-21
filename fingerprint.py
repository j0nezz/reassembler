import json
import os

import pandas as pd

__all__ = ['flatten_fingerprint', 'read_fingerprints']


# Function to extract nested data and create new records with the desired format
def flatten_fingerprint(data):
    new_attack_vectors = []

    for attack_vector in data['attack_vectors']:
        for source_ip in attack_vector['source_ips']:
            new_attack_vector = {
                'key': data['key'],
                'source_ip': source_ip,
                'source_ip_real': attack_vector['source_ips_real'][source_ip],
                'ttl': attack_vector['ttl_by_source'][source_ip],
                'nr_packets': attack_vector['nr_packets_by_source'][source_ip],
                **{k: attack_vector[k] for k in ['service', 'protocol', 'duration_seconds', 'time_start', 'detection_threshold']},
                **{k: data[k] for k in ['target', 'location', 'location_real']}
            }
            new_attack_vectors.append(new_attack_vector)

    data['attack_vectors'] = new_attack_vectors
    return data


def read_fingerprints(path: str, location="") -> pd.DataFrame:
    # create an empty list to store the DataFrames
    dfs = []

    # loop over each JSON file in the folder
    for filename in os.listdir(path):
        if filename.endswith('.json'):
            with open(os.path.join(path, filename)) as f:
                # load the JSON data into a Python dictionary
                data = json.load(f)
                reformatted_data = flatten_fingerprint(data)
                df = pd.json_normalize(reformatted_data, 'attack_vectors')
                dfs.append(df)
    return pd.concat(dfs, ignore_index=True)
