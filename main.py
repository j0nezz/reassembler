import random

from matplotlib import pyplot as plt

from evaluation import evaluate_base_scenario

random.seed(12)


def plot_nr_source_vs_observing_fp(data):
    plt.plot([len(d['ground_truth']['sources']) for d in data],
             [d['ground_truth']['nr_locations_observing_attack'] for d in data], 'o')
    plt.xlabel('Length of sources')
    plt.ylabel('Number of locations observing attack')
    plt.title('Observations')
    plt.show()


def plot_spoofed_vs_discarded_nodes(data, spoofed_pct):
    plt.plot(spoofed_pct, [d['sources']['pct_spoofed'] for d in data], 'o')
    plt.xlabel('% Spoofed')
    plt.ylabel('% Estimated')
    plt.title('Actual Spoofed Pct. vs Estimated Pct.')
    plt.show()


if __name__ == '__main__':
    evaluate_base_scenario()

    """
    summaries = []
    spoofed_pct = []
    for i in range(10):
        spoofed_pct.append(i * 0.1)
        print(f"Evaluating Run {i + 1} with {0.1 * i} spoofed sources")
        fp = scenario.set_spoofed_pct(i * 0.1).simulate_attack().fingerprints
        summary = Reassembler(fingerprint_data=fp).reassemble().add_ground_truth_data(scenario.target,
                                                                                      scenario.sources).save_to_json(
            f'./spoofed').summary
        summaries.append(summary)

    plot_spoofed_vs_discarded_nodes(summaries, spoofed_pct)"""
