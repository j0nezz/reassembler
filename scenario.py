import hashlib
import itertools
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta

import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.pyplot import figure
from netaddr import IPNetwork, IPAddress
from networkx import Graph

figure(figsize=(10, 10), dpi=120)

__all__ = ['create_network', 'draw_network', 'generate_background_traffic', 'generate_attack_fingerprint']

COLORS = ["tab:purple", "tab:green", "tab:orange", "tab:blue", "tab:olive", 'gold', 'teal']


def create_hierarchical_subnet(root: IPNetwork, levels=3, prefixlen=4, max_clients=5, color='tab:blue'):
    graph = nx.Graph()
    graph.add_node(root.ip, ip=root.ip, level=1, client=False, spoofed=False)

    def create_subnet_nodes(parent_subnet, level):
        if level == levels:
            ips = random.sample(list(parent_subnet.iter_hosts()), random.randint(2, max_clients))
            for p in ips:
                graph.add_node(p, ip=p, level=level + 1,
                               client=True, spoofed=bool(random.getrandbits(1)),
                               spoofed_ip=IPAddress(random.randint(0, 2 ** 32)))
                graph.add_edge(parent_subnet.ip, p, color=color, level=level + 1, ms=random.uniform(0.001, 0.01))
            return

        nr_nodes = random.randint(1, max_clients)
        i = 0
        for s in parent_subnet.subnet(parent_subnet.prefixlen + prefixlen):
            i += 1
            if i > nr_nodes:
                break
            s = s.next()

            graph.add_node(s.ip, ip=s.ip, level=level + 1, client=False, spoofed=False)
            # weight is the simulated duration in ms
            graph.add_edge(parent_subnet.ip, s.ip, color=color, level=level + 1, ms=random.uniform(0.001, 0.01))
            create_subnet_nodes(s, level + 1)

    create_subnet_nodes(root, 0)

    return graph


def create_network(subnets: list[IPNetwork], max_levels=3, max_clients=5):
    subgraphs = [create_hierarchical_subnet(s, levels=random.randint(1, max_levels), color=COLORS[i],
                                            max_clients=random.randint(1, max_clients)) for i, s in
                 enumerate(subnets)]

    F = nx.compose_all(subgraphs)

    edges = [(a.ip, b.ip, {'color': 'r', 'level': 0, 'ms': random.uniform(0.001, 0.01)}) for a, b in
             itertools.combinations(subnets, 2)]
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
    labels = {n: str(get_real_or_spoofed_ip(data)) for n, data in G.nodes(data=True)}

    edge_widths = [1.5 if level == 0 else 1 / level for level in nx.get_edge_attributes(G, 'level').values()]
    node_sizes = [40 - level * 7 for level in nx.get_node_attributes(G, 'level').values()]

    nx.draw(G, with_labels=True, font_size=10, node_size=node_sizes, width=edge_widths, edge_color=edge_colors,
            node_color=node_colors, labels=labels)
    plt.show()


def calculate_hash(data):
    key = hashlib.md5(json.dumps(data, sort_keys=True).encode('utf-8')).hexdigest()
    data['key'] = key
    return data


def get_real_or_spoofed_ip(data: dict):
    if data.get('spoofed', False):
        return data.get('spoofed_ip')
    return data.get('ip')


def generate_background_traffic(G, num_background_traffic):
    combinations = [(x, y) for x, y in itertools.combinations(G.nodes, 2) if x != y]
    selected_combinations = random.sample(combinations, num_background_traffic)
    return [(source, target, nx.shortest_path(G, source, target), False) for source, target in selected_combinations]


def generate_attack_fingerprint(G, sources, target, num_background_fp=10):
    common_ttls = [32, 64, 128, 255]
    intermediary_nodes = {}  # by target

    # Iterate through each source
    background_traffic = generate_background_traffic(G, num_background_fp)
    attack_traffic = [(source, target, nx.shortest_path(G, source, target), True) for source in sources]

    print("Traffic", attack_traffic + background_traffic)

    for source, target, path, is_attack in attack_traffic + background_traffic:
        ttl = random.choice(common_ttls)

        # Generate random start time and duration for the attack
        start_time = datetime.utcfromtimestamp(0) + timedelta(seconds=random.uniform(0, 10))
        duration = random.uniform(60, 180) if is_attack else random.uniform(10, 70)
        nr_packets = round(random.uniform(10e3, 10e6)) if is_attack else round(random.uniform(10, 10e4))
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
                    "sources": set(),
                    "sources_real": set(),
                    "time_start": [],
                    "duration_seconds": [],
                    "nr_packets": [],
                    "nr_megabytes": [],
                }

            if i > 0:
                prev_node = path[i - 1]
                edge_weight = G[prev_node][node]['ms']
                accumulated_weight += edge_weight

            # TODO: if spoofed, add the spoofed IP address to the fingerprint
            intermediary_nodes[node]["targets"][target]["ttl"][ttl] += nr_packets
            intermediary_nodes[node]["targets"][target]["sources_real"].add(source)
            # includes spoofed IPs
            intermediary_nodes[node]["targets"][target]["sources"].add(
                get_real_or_spoofed_ip(G.nodes(data=True)[source]))
            intermediary_nodes[node]["targets"][target]["time_start"].append(
                start_time + timedelta(seconds=accumulated_weight))
            intermediary_nodes[node]["targets"][target]["duration_seconds"].append(duration)
            intermediary_nodes[node]["targets"][target]["nr_packets"].append(
                (get_real_or_spoofed_ip(G.nodes(data=True)[source]), nr_packets))
            intermediary_nodes[node]["targets"][target]["nr_megabytes"].append(
                (get_real_or_spoofed_ip(G.nodes(data=True)[source]), nr_megabytes))

            ttl -= 1

    # Generate attack fingerprints for each intermediary node
    fingerprints = []
    for node, node_data in intermediary_nodes.items():
        for target, target_data in node_data["targets"].items():
            ttl_dict = target_data["ttl"]
            fp_sources = list(target_data["sources"])
            fp_sources_real = list(target_data["sources_real"])

            # Calculate the total number of packets for this intermediary node
            total_packets = sum(count for _, count in target_data["nr_packets"])

            # Normalize the TTL values
            ttl_normalized = {ttl: count / total_packets for ttl, count in ttl_dict.items()}

            # Calculate the earliest start time and latest end time
            min_start_time = min(target_data["time_start"])
            max_end_time = max(
                t1 + timedelta(seconds=t2) for t1, t2 in
                zip(target_data["time_start"], target_data["duration_seconds"]))

            fingerprint = {
                "attack_vectors": [
                    {
                        "service": None,  # TODO: Different Services
                        "protocol": "TCP",  # TODO: Also support different protocols
                        "source_ips": sorted([str(s) for s in fp_sources]),
                        "source_ips_real": sorted([str(s) for s in fp_sources_real]),
                        "ttl": ttl_normalized,
                        # TODO TTL map
                        "ttl_by_source": None,
                        "time_start": min_start_time.isoformat(),
                        "duration_seconds": (max_end_time - min_start_time).total_seconds(),
                        # TODO nr_packets map
                        "nr_packets_by_source": None,
                        "nr_packets": sum(n for _, n in target_data["nr_packets"]),
                        "nr_megabytes": sum(n for _, n in target_data["nr_megabytes"]),

                    }
                ],
                "target": str(G.nodes[target]["ip"]),
                "location": str(get_real_or_spoofed_ip(G.nodes(data=True)[node])),
                "location_real": str(G.nodes[node]["ip"])
            }
            fingerprints.append(fingerprint)

    str_sources = list(map(str, sources))
    # Filter fingerprints from attack sources, as we do not have this data in a real world scenario
    filtered_fingerprints = [f for f in fingerprints if f['location_real'] not in str_sources]

    return list(map(calculate_hash, filtered_fingerprints))
