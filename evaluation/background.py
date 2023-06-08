from netaddr import IPNetwork

from generator import Generator
from logger import LOGGER
from reassembler import Reassembler


def evaluate_background_traffic():
    n2 = Generator([IPNetwork(f"{10 + i}.0.0.0/8") for i in range(15)], max_levels=6, max_clients=5, spoofed_pct=0.25)
    summaries = []
    bgs = []
    for i in range(1):
        bg = 5000
        scenario = n2.set_random_attack_sources(100).add_background_traffic(bg).simulate_attack()
        LOGGER.info(f"Run {i} with {bg} background")
        bgs.append(bg)
        summary = Reassembler(fingerprint_data=scenario.fingerprints).reassemble(draw_percentiles=True).add_ground_truth_data(scenario.target, scenario.sources).summary
        summaries.append(summary)
