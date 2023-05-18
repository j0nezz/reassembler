import random

from matplotlib import pyplot as plt
from netaddr import IPNetwork

from fingerprint import read_fingerprints
from reassembler import Reassembler
from scenario import create_network, draw_network, generate_attack_fingerprint

random.seed(12)


def run_full_workflow(G, nr_sources=10, nr_background=100):
    clients = [n for n, data in G.nodes(data=True) if data['client']]
    sources = random.sample(clients, nr_sources)
    possible_targets = [n for n, data in G.nodes(data=True) if data['client'] and not data.get('spoofed', False) and not n in sources]
    target = random.choice(possible_targets)

    generate_attack_fingerprint(G, sources, target, num_background_fp=nr_background, output_folder='./fingerprints')
    r = Reassembler("./fingerprints").reassemble().add_ground_truth_data(target, sources)

    return r.summary


def plot_nr_source_vs_observing_fp(data):
    plt.plot([len(d['ground_truth']['sources']) for d in data], [d['ground_truth']['nr_locations_observing_attack'] for d in data], 'o')
    plt.xlabel('Length of sources')
    plt.ylabel('Number of locations observing attack')
    plt.title('Observations')
    plt.show()


if __name__ == '__main__':
    summaries = []
    nr_subnets = [IPNetwork(f"{10 + i}.0.0.0/8") for i in range(10)]
    G = create_network(nr_subnets, max_clients=5, max_levels=4)
    print("Number of Network nodes", G.number_of_nodes())
    for i in range(20):
        print(f"Evaluating Run {i+1} with {5*(i+1)} sources")
        summaries.append(run_full_workflow(G, nr_sources=5*(i+1)))

    plot_nr_source_vs_observing_fp(summaries)
