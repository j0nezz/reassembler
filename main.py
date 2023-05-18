import random

from netaddr import IPNetwork

from fingerprint import read_fingerprints
from reassembler import Reassembler
from scenario import create_network, draw_network, generate_attack_fingerprint

random.seed(12)


def run_full_workflow(nr_subnets=5, nr_sources=10, nr_background=100):
    nr_subnets = [IPNetwork(f"{10 + i}.0.0.0/16") for i in range(nr_subnets)]
    G = create_network(nr_subnets, max_clients=10)
    clients = [n for n, data in G.nodes(data=True) if data['client']]
    sources = random.sample(clients, nr_sources)
    possible_targets = [n for n, data in G.nodes(data=True) if data['client'] and not data.get('spoofed', False) and not n in sources]
    target = random.choice(possible_targets)

    generate_attack_fingerprint(G, sources, target, num_background_fp=nr_background, output_folder='./fingerprints')
    Reassembler("./fingerprints").reassemble().add_ground_truth_data(target, sources).save_to_json(baseDir="./my-directory")


if __name__ == '__main__':
    for i in range(2):
        # TODO: Use Logger instead of print()
        print(f"Evaluating Run {i+1} with {5*(i+1)} sources")
        run_full_workflow(nr_subnets=20, nr_sources=5*(i+1))