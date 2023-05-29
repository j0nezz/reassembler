from matplotlib import pyplot as plt
from netaddr import IPNetwork

from generator import Generator
from reassembler import Reassembler


def plot_spoofed_vs_discarded_nodes(data, spoofed_pct):
    plt.rc('font', size=15)

    fig, ax1 = plt.subplots()
    ax1.plot(spoofed_pct, [d['sources']['pct_spoofed'] for d in data], color='tab:blue')
    ax1.set_ylabel('Estimated Percentage', color='tab:blue')
    ax1.yaxis.set_tick_params(labelcolor='tab:blue')
    ax1.set_ylim(0, 1)

    ax2 = ax1.twinx()

    ax2.plot(spoofed_pct, [d['sources']['nr_sources'] for d in data], color='tab:orange')
    ax2.plot(spoofed_pct, [d['sources']['nr_sources']-(d['sources']['nr_sources'] * d['sources']['pct_spoofed']) for d in data], color='tab:green', label="Normalized", linestyle='--')
    ax2.set_ylabel('Observed Nr. Sources', color='tab:orange')
    ax2.yaxis.set_tick_params(labelcolor='tab:orange')
    ax2.axhline(y=100, color='tab:red', linestyle='--', label='Actual nr. sources')

    ax1.set_xlabel('% Spoofed')

    lines_1, labels_1 = ax1.get_legend_handles_labels()
    lines_2, labels_2 = ax2.get_legend_handles_labels()
    ax1.legend(lines_1 + lines_2, labels_1 + labels_2, loc="upper left")

    plt.tight_layout()
    plt.savefig('spoofed-experiment-pool-10000.png', dpi=300)
    plt.show()


def evaluate_spoofed_vs_discarded_nodes():
    summaries = []
    spoofed_pct = []
    scenario = (
        Generator([IPNetwork(f"{10 + i}.0.0.0/8") for i in range(15)], max_levels=6, max_clients=5, spoofed_pct=0)
        .set_random_attack_sources(100))
    for i in range(21):
        spoofed_pct.append(i * 0.05)
        print(f"Evaluating Run {i + 1} with {0.05 * i} spoofed sources")
        fp = scenario.set_spoofed_pct(i * 0.05).simulate_attack().fingerprints
        summary = Reassembler(fingerprint_data=fp).reassemble().add_ground_truth_data(scenario.target,
                                                                                      scenario.sources).summary
        summaries.append(summary)

    plot_spoofed_vs_discarded_nodes(summaries, spoofed_pct)
