import copy

import pandas as pd
from matplotlib import pyplot as plt
from netaddr import IPNetwork

from generator import Generator
from logger import LOGGER
from reassembler import Reassembler

import matplotlib.colors as mcolors


def plot(dropped, summaries):
    plt.rc('font', size=15)
    ground_truth = {
        'Estimated': [summary['intermediate_nodes']['nr_intermediate_nodes'] for summary in summaries],
        'Discarded': [summary['intermediate_nodes']['discarded_intermediate_nodes'] for summary in summaries],
        'Ground truth': [summary['ground_truth']['nr_locations_observing_attack'] for summary in summaries],
    }
    cmap = mcolors.ListedColormap(['tab:red', 'tab:blue', 'tab:green'])

    df = pd.DataFrame(ground_truth, index=dropped)
    df['discarded_relative'] = df['Discarded'] / (df['Estimated'] + df['Discarded'])

    df.plot(y=["Discarded", "Estimated", "Ground truth"], kind="bar", ylabel='Intermediate Nodes', xlabel='% Dropped Fingerprints', cmap=cmap)
    plt.tight_layout()
    plt.savefig("intermediate-nodes-eval.png", dpi=300)
    plt.show()


def evaluate_intermediate_nodes_with_fp_dropped():
    n2 = Generator([IPNetwork(f"{10 + i}.0.0.0/8") for i in range(15)], max_levels=6, max_clients=5, spoofed_pct=0.25)
    scenario = n2.set_random_attack_sources(100).add_background_traffic(200).simulate_attack()
    summaries = []
    dropped = []
    for i in range(10):
        fp = copy.deepcopy(scenario.fingerprints)
        drop_pct = round(i * 0.1, 1)
        LOGGER.debug(f"Run {i} with {drop_pct} dropped")
        dropped.append(drop_pct)
        summary = Reassembler(fingerprint_data=fp).drop_fingerprints(drop_pct).reassemble().add_ground_truth_data(scenario.target, scenario.sources).summary
        summaries.append(summary)

    plot(dropped, summaries)






