import itertools
import networkx as nx
import random
from matplotlib.pyplot import figure
from netaddr import IPNetwork
import matplotlib.pyplot as plt

from collections import defaultdict
from datetime import datetime, timedelta

figure(figsize=(10, 10), dpi=120)
random.seed(12)

__all__ = ['create_network', 'draw_network', 'generate_attack_fingerprint']


def create_network(num_subnets, participants_per_subnet, num_routers, routers_per_layer):
    G = nx.Graph()

    # Generate IP addresses for router subnets
    router_subnets = [IPNetwork(f"172.16.{i + 1}.0/24") for i in range(num_routers)]

    # Add router nodes to the graph and initialize their IP assignment dictionary
    router_assigned_ips = {}
    for i in range(num_routers):
        router_id = f"R{i + 1}"
        G.add_node(router_id, ip=str(router_subnets[i].ip), subnet=router_subnets[i])
        router_assigned_ips[router_id] = set()

    # Generate participants and add them to the graph
    layers = [list(range(i, i + routers_per_layer)) for i in range(0, num_routers, routers_per_layer)]

    participant_counter = 1
    for _ in range(num_subnets * participants_per_subnet):
        # Randomly choose a router from any layer
        random_layer = random.choice(layers)
        random_router_index = random.choice(random_layer)
        random_router_id = f"R{random_router_index + 1}"
        router_subnet = G.nodes[random_router_id]["subnet"]

        # Generate a unique participant IP based on the router's subnet and assigned IPs
        while True:
            candidate_ip = str(router_subnet[random.randint(2, 254)])
            if candidate_ip not in router_assigned_ips[random_router_id]:
                participant_ip = candidate_ip
                router_assigned_ips[random_router_id].add(participant_ip)
                break

        participant_id = f"P{participant_counter}"
        participant_counter += 1

        G.add_node(participant_id, ip=participant_ip)
        G.add_edge(participant_id, random_router_id, weight=random.uniform(0.001, 0.01))

    # Add connections between routers in a hierarchical backbone structure

    # Connect routers in each layer
    for layer in layers:
        for i, j in itertools.combinations(layer, 2):
            G.add_edge(f"R{i + 1}", f"R{j + 1}", weight=random.uniform(0.001, 0.01))

    # Connect routers between layers
    for i in range(len(layers) - 1):
        for j in layers[i]:
            for k in layers[i + 1]:
                G.add_edge(f"R{j + 1}", f"R{k + 1}", weight=random.uniform(0.001, 0.01))

    return G


def draw_network(G):
    pos = nx.spring_layout(G, seed=12)

    # Separate routers and participants
    router_nodes = [n for n in G.nodes if n.startswith("R")]
    participant_nodes = [n for n in G.nodes if n.startswith("P")]

    # Draw nodes
    nx.draw_networkx_nodes(G, pos, nodelist=router_nodes, node_color='orange', node_size=200, label="Routers")
    nx.draw_networkx_nodes(G, pos, nodelist=participant_nodes, node_color='lightblue', node_size=150,
                           label="Participants")

    # Draw edges
    nx.draw_networkx_edges(G, pos)
    # Add the edge labels
    edge_labels_raw = nx.get_edge_attributes(G, "weight")
    edge_labels = {k: f"{v * 1000:.2f} ms" for k, v in edge_labels_raw.items()}
    pos_edge_labels = {}
    for key, value in pos.items():
        if key in edge_labels:
            pos_edge_labels[key] = value
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)

    # Draw IP address labels
    ip_labels = {node: data['ip'] for node, data in G.nodes(data=True)}
    nx.draw_networkx_labels(G, pos, labels=ip_labels, font_size=8, font_color='red', font_family='sans-serif',
                            font_weight='bold', verticalalignment='bottom')

    # Draw node labels
    node_labels = {node: node for node in G.nodes}
    label_pos = {k: [v[0], v[1] + 0.05] for k, v in pos.items()}
    nx.draw_networkx_labels(G, label_pos, labels=node_labels, font_size=10, font_color='blue', font_family='sans-serif',
                            font_weight='bold')

    plt.axis('off')
    plt.show()


def generate_attack_fingerprint(G, sources, target):
    common_ttls = [32, 64, 128, 255]
    intermediary_nodes = defaultdict(
        lambda: {"ttl": defaultdict(int), "sources": set(), "time_start": [], "duration_seconds": [], "nr_packets": [],
                 "nr_megabytes": []})

    # Iterate through each source
    for source in sources:
        path = nx.shortest_path(G, source, target)
        ttl = random.choice(common_ttls)

        # Generate random start time and duration for the attack
        start_time = datetime.utcfromtimestamp(0) + timedelta(seconds=random.uniform(0, 10))
        duration = random.uniform(60, 120)
        nr_packets = round(random.uniform(0, 10e6))
        nr_megabytes = round(nr_packets / random.uniform(1000, 5000), 2)

        accumulated_weight = 0

        # Calculate the TTL and duration for each intermediary node in the path
        for i in range(len(path)):
            node = path[i]

            if i > 0:
                prev_node = path[i - 1]
                edge_weight = G[prev_node][node]['weight']
                accumulated_weight += edge_weight

            intermediary_nodes[node]["ttl"][ttl] += 1  # Increase count for the observed ttl value
            intermediary_nodes[node]["sources"].add(source)
            intermediary_nodes[node]["time_start"].append(start_time + timedelta(seconds=accumulated_weight))
            intermediary_nodes[node]["duration_seconds"].append(duration)
            intermediary_nodes[node]["nr_packets"].append((source, nr_packets))
            intermediary_nodes[node]["nr_megabytes"].append((source, nr_megabytes))

            ttl -= 1

    # Generate attack fingerprints for each intermediary node
    fingerprints = []
    for node, node_data in intermediary_nodes.items():
        ttl_dict = node_data["ttl"]
        sources = list(node_data["sources"])

        # Normalize the TTL values
        ttl_count = sum(ttl_dict.values())
        ttl_normalized = {ttl: count / ttl_count for ttl, count in ttl_dict.items()}

        # Calculate the earliest start time and latest end time
        min_start_time = min(node_data["time_start"])
        max_end_time = max(
            t1 + timedelta(seconds=t2) for t1, t2 in zip(node_data["time_start"], node_data["duration_seconds"]))

        fingerprint = {
            "attack_vectors": [
                {
                    "source_ips": [G.nodes[s]["ip"] for s in sources],
                    "source_ips_name": sources,
                    "ttl": ttl_normalized,
                    "time_start": min_start_time.isoformat(),
                    "duration_seconds": (max_end_time - min_start_time).total_seconds(),
                    "nr_packets": sum(n for _, n in node_data["nr_packets"]),
                    "nr_megabytes": sum(n for _, n in node_data["nr_megabytes"]),

                }
            ],
            "target": G.nodes[target]["ip"],
            "target_name": target,
            "location": G.nodes[node]["ip"],
            "location_name": node
        }
        fingerprints.append(fingerprint)

    return fingerprints
