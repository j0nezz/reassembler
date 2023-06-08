import random

from netaddr import IPNetwork

from generator import Generator
# from evaluation import evaluate_base_scenario
# from evaluation import evaluate_background_traffic
# from evaluation import evaluate_intermediate_nodes_with_fp_dropped
# from evaluation import evaluate_spoofed_vs_discarded_nodes, evaluate_spoofed_vs_inferred_distance
from reassembler import Reassembler

random.seed(12)

if __name__ == '__main__':
    # Create Simulated Network
    n1 = Generator([IPNetwork(f"{10 + i}.0.0.0/8") for i in range(5)], max_levels=3, max_clients=5, spoofed_pct=0.25)
    # Simulate Attack
    n1.set_random_attack_sources(5).add_background_traffic(10).simulate_attack().save_to_json('./example')
    # Run Reassembler
    Reassembler(fingerprint_folder='./example').reassemble().save_to_json('./example-fp')

    # === Evaluation ===
    # Uncomment to run an evaluation

    # evaluate_base_scenario()
    # evaluate_spoofed_vs_discarded_nodes()
    # evaluate_background_traffic()
    # evaluate_intermediate_nodes_with_fp_dropped()

    # === End Evaluation ===
