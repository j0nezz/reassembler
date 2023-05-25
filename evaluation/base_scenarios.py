import time

from matplotlib.pyplot import figure
from netaddr import IPNetwork

from generator import Generator
from reassembler import Reassembler


def measure_execution_time(func, name=""):
    start_time = time.time()
    res = func()
    end_time = time.time()
    print(f"Executed {name} in {end_time - start_time} seconds.")
    return res


def evaluate_base_scenario():
    figure(figsize=(12, 8), dpi=120)
    n1 = Generator([IPNetwork(f"{10 + i}.0.0.0/8") for i in range(5)], max_levels=3, max_clients=5, spoofed_pct=0.25)
    print("Total Nodes N1", n1.network.number_of_nodes())

    n2 = Generator([IPNetwork(f"{10 + i}.0.0.0/8") for i in range(15)], max_levels=6, max_clients=5, spoofed_pct=0.25)
    print("Total Nodes Large", n2.network.number_of_nodes())

    # Scenario 1
    s1 = measure_execution_time(
        lambda: (n1.set_random_attack_sources(5)
                 .add_background_traffic(10)
                 .simulate_attack()
                 .save_to_json('./base-scenarios/fp/s1')), "Scenario S1")

    measure_execution_time(
        lambda: (Reassembler(fingerprint_data=s1.fingerprints)
                 .reassemble()
                 .add_ground_truth_data(s1.target, s1.sources)
                 .save_to_json('./base-scenarios/global-fp/s1')), "Reassembler S1")

    # Scenario 2
    s2 = measure_execution_time(
        lambda: (n1.set_random_attack_sources(20)
                 .add_background_traffic(50)
                 .simulate_attack()
                 .save_to_json('./base-scenarios/fp/s2')), "Scenario S2")

    measure_execution_time(
        lambda: (Reassembler(fingerprint_data=s2.fingerprints)
                 .reassemble()
                 .add_ground_truth_data(s2.target, s2.sources)
                 .save_to_json('./base-scenarios/global-fp/s2')), "Reassembler S2")

    # Scenario 3
    s3 = measure_execution_time(
        lambda: (n2.set_random_attack_sources(100)
                 .add_background_traffic(200)
                 .simulate_attack()
                 .save_to_json('./base-scenarios/fp/s3')), "Scenario S3")

    measure_execution_time(
        lambda: (Reassembler(fingerprint_data=s3.fingerprints)
                 .reassemble()
                 .add_ground_truth_data(s3.target, s3.sources)
                 .save_to_json('./base-scenarios/global-fp/s3')), "Reassembler S3")

    # Scenario 4
    s4 = measure_execution_time(
        lambda: (n2.set_random_attack_sources(500)
                 .add_background_traffic(1000)
                 .simulate_attack()
                 .save_to_json('./base-scenarios/fp/s4')), "Scenario S4")

    measure_execution_time(
        lambda: (Reassembler(fingerprint_data=s4.fingerprints)
                 .reassemble()
                 .add_ground_truth_data(s4.target, s4.sources)
                 .save_to_json('./base-scenarios/global-fp/s4')), "Reassembler S4")

