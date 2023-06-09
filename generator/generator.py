import itertools
import json
import os
import random
import shutil
from collections import defaultdict
from datetime import datetime, timedelta

import matplotlib.pyplot as plt
import networkx as nx
from netaddr import IPNetwork, IPAddress
from networkx import Graph

from logger import LOGGER
from utils import calculate_hash

__all__ = ['Generator']

COLORS = ["tab:purple", "tab:green", "tab:orange", "tab:blue", "tab:olive", 'gold', 'teal']

random.seed(12)

SPOOFED_IP_POOL = [IPAddress(random.randint(0, 2 ** 32)) for i in range(1000)]


class Generator:
    """
    Helper Class providing a fluent API for the network simulation and fingerprint generation.
    """
    def __init__(self, subnets: list[IPNetwork], max_levels=3, max_clients=5, spoofed_pct=0.5):
        self.max_levels = max_levels
        self.max_clients = max_clients
        self.spoofed_pct = spoofed_pct
        self.subnets = subnets
        self.network = create_network(subnets, max_levels=max_levels, max_clients=max_clients, spoofed_pct=spoofed_pct)

        self.clients = [n for n, data in self.network.nodes(data=True) if data['client']]
        self.target = random.choice(self.clients)
        self.sources = [random.choice(self.clients)]
        self.background_traffic = []
        self.fingerprints = []

    def set_random_attack_sources(self, nr_sources):
        bg_sources = [t[0] for t in self.background_traffic]
        possible_sources = [c for c in self.clients if c != self.target and c not in bg_sources]
        self.sources = random.sample(possible_sources, nr_sources)
        return self

    def add_background_traffic(self, num_background_traffic_routes):
        self.background_traffic = generate_background_traffic(self.network, num_background_traffic_routes, self.target,
                                                              self.sources)
        return self

    def draw_network(self):
        draw_network(self.network)

        return self

    def set_spoofed_pct(self, updated_pct):
        for node, attrs in self.network.nodes(data=True):
            if attrs.get('client', False):
                self.network.nodes[node]['spoofed'] = random.random() <= updated_pct

        return self

    def simulate_attack(self):
        self.fingerprints = generate_attack_fingerprint(self.network, self.sources, self.target,
                                                        self.background_traffic)
        return self

    def save_to_json(self, output_folder='fingerprints', overwrite_files=True):
        if len(self.fingerprints) == 0:
            raise ValueError("Please run a simulation first")

        LOGGER.info(f"Saving {len(self.fingerprints)} fingerprints...")

        if os.path.exists(output_folder) and overwrite_files:
            shutil.rmtree(output_folder)

        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        for fingerprint in self.fingerprints:
            output_file = os.path.join(output_folder, f"{fingerprint['key']}.json")
            with open(output_file, "w") as f:
                json.dump(fingerprint, f, indent=2)

        LOGGER.info("Saved!")
        return self


def create_subnet(root: IPNetwork, levels=3, prefixlen=4, max_clients=5, color='tab:blue', spoofed_pct=0.8):
    LOGGER.info(f"Initializing Subnet {str(root)}")
    graph = nx.Graph()
    graph.add_node(root.ip, ip=root.ip, level=1, client=False, spoofed=False)

    def create_subnet_nodes(parent, level):
        if level == levels:
            ips = random.sample(list(parent.iter_hosts()), random.randint(1, max_clients))
            for p in ips:
                graph.add_node(p, ip=p, level=level + 1,
                               client=True, spoofed=random.random() <= spoofed_pct,
                               spoofed_ips=random.sample(SPOOFED_IP_POOL, random.randint(7, 25)))
                graph.add_edge(parent.ip, p, color=color, level=level + 1, ms=random.uniform(1, 100))
            return

        nr_nodes = random.randint(1, max_clients)
        i = 0
        for s in parent.subnet(parent.prefixlen + prefixlen):
            i += 1
            if i > nr_nodes:
                break
            s = s.next()

            graph.add_node(s.ip, ip=s.ip, level=level + 1, client=False, spoofed=False)
            # weight is the simulated duration in ms
            graph.add_edge(parent.ip, s.ip, color=color, level=level + 1, ms=random.uniform(1, 100))
            create_subnet_nodes(s, level + 1)

    create_subnet_nodes(root, 0)

    return graph


def create_network(subnets: list[IPNetwork], max_levels=3, max_clients=5, spoofed_pct=0.5):
    LOGGER.info("Creating Network")
    subgraphs = [create_subnet(s, levels=random.randint(1, max_levels), color=COLORS[i % len(COLORS)],
                               max_clients=random.randint(2, max_clients), prefixlen=3, spoofed_pct=spoofed_pct) for
                 i, s in
                 enumerate(subnets)]

    F = nx.compose_all(subgraphs)
    n = len(subnets)

    if len(subnets) <= 1:
        return F

    # Ring topology
    edges = [(subnets[i].ip, subnets[(i + 1) % n].ip, {'color': 'r', 'level': 0, 'ms': random.uniform(1, 100)}) for
             i in range(n)]

    # Add random connections to create a partial mesh
    m = round(n / 2)
    partial_mesh = [(u.ip, v.ip, {'color': 'r', 'level': 0, 'ms': random.uniform(1, 100)}) for u, v in
                    random.sample(list(itertools.combinations(subnets, 2)), m)]

    edges.extend(partial_mesh)

    F.add_edges_from(edges)

    return F


def get_node_color(data: dict):
    if data.get('spoofed', False):
        return 'r'
    if data.get('client', False):
        return 'k'
    return 'dimgrey'


def draw_network(G: Graph):
    edge_colors = nx.get_edge_attributes(G, 'color').values()
    node_colors = [get_node_color(data) for _, data in G.nodes(data=True)]
    labels = {n: str(data['ip']) for n, data in G.nodes(data=True)}

    edge_widths = [2 if level == 0 else 1.5 / level for level in nx.get_edge_attributes(G, 'level').values()]
    node_sizes = [40 - level * 7 for level in nx.get_node_attributes(G, 'level').values()]

    pos = nx.spring_layout(G)

    nx.draw(G, pos, with_labels=False, font_size=14, node_size=node_sizes, width=edge_widths, edge_color=edge_colors,
            node_color=node_colors, labels=labels)

    # Uncomment to print IPs of Network nodes
    # label_pos = {node: (coords[0], coords[1] + 0.05) for node, coords in pos.items()}
    # nx.draw_networkx_labels(G, label_pos, labels=labels, font_size=16)

    plt.show()


def generate_background_traffic(G, amount, target, sources, targeted_pct=0.2):
    if amount == 0:
        return []

    unrelated = [(x, y) for x, y in itertools.combinations(G.nodes, 2) if x != y and y != target]
    unrelated_sample = random.sample(unrelated, int(amount * (1 - targeted_pct)))

    targeted = [(n, target) for n, data in G.nodes(data=True) if not data.get('spoofed', False) and n not in sources]
    targeted_sample = random.sample(targeted, int(amount * targeted_pct))
    return [(s, t, nx.shortest_path(G, s, t, weight='ms'), False) for s, t in
            unrelated_sample + targeted_sample]


def generate_attack_fingerprint(G, sources, attack_target, background_traffic):
    LOGGER.info(f"Generate Attack with {len(sources)} Sources and {len(background_traffic)} BG traffic")
    common_ttls = [32, 64, 128, 255]
    intermediary_nodes = {}  # by target

    # Iterate through each source
    attack_traffic = [(source, attack_target, nx.shortest_path(G, source, attack_target, weight='ms'), True) for source
                      in sources]
    for source, target, path, is_attack in attack_traffic + background_traffic:
        ttl = random.choice(common_ttls)

        # Generate random start time and duration for the attack
        start_time = datetime.now() + timedelta(seconds=random.uniform(0, 10))
        duration = random.uniform(60, 600) if is_attack else random.uniform(10, 70)
        nr_packets = round(random.uniform(10e3, 10e6)) if is_attack else round(random.uniform(10e2, 10e5))
        nr_megabytes = round(nr_packets / random.uniform(1000, 5000), 2)

        accumulated_weight = 0

        # Calculate the TTL and duration for each intermediary node in the path
        for i in range(len(path)):
            node = path[i]

            # Initialize the "targets" dictionary in the `intermediary_nodes` dictionary
            if node not in intermediary_nodes:
                intermediary_nodes[node] = {
                    "targets": {},
                }
            if target not in intermediary_nodes[node]["targets"]:
                intermediary_nodes[node]["targets"][target] = {
                    "ttl": defaultdict(int),
                    "ttl_by_source": defaultdict(list),
                    "sources": set(),
                    "sources_real": defaultdict(str),
                    "time_start": [],
                    "duration_seconds": [],
                    "nr_packets": [],
                    "nr_packets_by_source": defaultdict(int),
                    "nr_megabytes": [],
                    "is_attack": False
                }
            if is_attack:
                intermediary_nodes[node]["targets"][target]["is_attack"] = True

            # calculate delay along path
            if i > 0:
                prev_node = path[i - 1]
                ms = G[prev_node][node]['ms']
                accumulated_weight += ms / 1000
            source_data = G.nodes(data=True)[source]

            # For spoofed sources, the calculation of e.g. packet_by_source is different
            # Hence a distinction is made here, but the resulting keys are the same
            if source_data.get('spoofed', False):
                spoofed_sources = list(map(str, source_data.get('spoofed_ips', [])))
                intermediary_nodes[node]["targets"][target]["ttl_by_source"].update(
                    {s: intermediary_nodes[node]["targets"][target]["ttl_by_source"].get(s, []) + [ttl] for s in
                     spoofed_sources})
                intermediary_nodes[node]["targets"][target]["sources_real"].update(
                    dict.fromkeys(spoofed_sources, str(source)))
                intermediary_nodes[node]["targets"][target]["sources"].update(spoofed_sources)
                intermediary_nodes[node]["targets"][target]["nr_packets"].append(nr_packets)
                intermediary_nodes[node]["targets"][target]["nr_packets_by_source"] \
                    .update({s: intermediary_nodes[node]["targets"][target]["nr_packets_by_source"][s] +
                                nr_packets / len(spoofed_sources) for s in spoofed_sources})
                intermediary_nodes[node]["targets"][target]["nr_megabytes"].extend(
                    (s, nr_megabytes / len(spoofed_sources)) for s in spoofed_sources)
            else:
                intermediary_nodes[node]["targets"][target]["ttl_by_source"][str(source)] = [ttl]
                intermediary_nodes[node]["targets"][target]["sources_real"][str(source)] = str(source)
                intermediary_nodes[node]["targets"][target]["sources"].add(str(source))
                intermediary_nodes[node]["targets"][target]["nr_packets"].append(nr_packets)
                intermediary_nodes[node]["targets"][target]["nr_packets_by_source"][str(source)] = nr_packets
                intermediary_nodes[node]["targets"][target]["nr_megabytes"].append((str(source), nr_megabytes))

            intermediary_nodes[node]["targets"][target]["ttl"][ttl] += nr_packets
            intermediary_nodes[node]["targets"][target]["time_start"].append(
                start_time + timedelta(seconds=accumulated_weight))
            intermediary_nodes[node]["targets"][target]["duration_seconds"].append(duration)
            intermediary_nodes[node]["targets"][target]["distance_to_target"] = len(path) - 1 - i
            # Decrease TTL on each hop
            ttl -= 1

    # Generate attack fingerprints for each intermediary node
    fingerprints = []
    for node, node_data in intermediary_nodes.items():
        # Calculate total packets through node
        total_packets_to_node = sum(sum(item["nr_packets"]) for item in node_data["targets"].values())
        for target, target_data in node_data["targets"].items():
            ttl_dict = target_data["ttl"]
            fp_sources = list(target_data["sources"])

            # Calculate the total number of packets for this intermediary node
            nr_packets_to_target = sum(target_data["nr_packets"])

            # Normalize the TTL values
            ttl_normalized = {ttl: count / nr_packets_to_target for ttl, count in ttl_dict.items()}

            # Calculate the earliest start time and latest end time
            min_start_time = min(target_data["time_start"])
            max_end_time = max(
                t1 + timedelta(seconds=t2) for t1, t2 in
                zip(target_data["time_start"], target_data["duration_seconds"]))
            fingerprint = {
                "attack_vectors": [
                    {
                        "service": None,
                        "protocol": "TCP",
                        "source_ips": sorted([str(s) for s in fp_sources]),
                        "source_ips_real": target_data["sources_real"],
                        "ttl": ttl_normalized,
                        "ttl_by_source": target_data['ttl_by_source'],
                        "time_start": min_start_time.isoformat(),
                        "duration_seconds": (max_end_time - min_start_time).total_seconds(),
                        "nr_packets_by_source": target_data['nr_packets_by_source'],
                        "nr_packets": nr_packets_to_target,
                        "nr_megabytes": sum(n for _, n in target_data["nr_megabytes"]),
                        "detection_threshold": nr_packets_to_target / total_packets_to_node,
                        "is_attack": target_data["is_attack"]

                    }
                ],
                "target": str(G.nodes[target]["ip"]),
                "location": str(G.nodes[node]["ip"]),
                "distance": target_data["distance_to_target"]
            }
            fingerprints.append(fingerprint)

    str_sources = list(map(str, sources))

    # Filter fingerprints from attack sources, as we do not have this data in a real world scenario
    filtered_fingerprints = [f for f in fingerprints if f['location'] not in str_sources]

    fingerprints_with_key = list(map(calculate_hash, filtered_fingerprints))

    return fingerprints_with_key
