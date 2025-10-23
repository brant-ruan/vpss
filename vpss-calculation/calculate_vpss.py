#!/usr/bin/env python3

import sys
import json
import math
import networkx as nx
import os

gav_ts_cg_file_path = "./timestamps/gav_ts_cg.json"
gav_ts_cg_file = None

W = [5, 2.5, 3, 1.5]
gamma = 500
L_norm = 10
k = 0.5
score_range = 10

meta_dir = "../dataset/meta"
res_dir = "./vpa_results"
output_dir = "./vpss_stats"


def load_cve_info(cve_id):
    cve_path = f"{meta_dir}/{cve_id}.json"
    if not os.path.exists(cve_path):
        print(f"Error: {cve_path} does not exist.")
        sys.exit(1)
    
    cve_info = load_json_file(cve_path)
    return cve_info


def get_earliest_ga_ts(ga):
    global gav_ts_cg_file
    if gav_ts_cg_file is None:
        gav_ts_cg_file = load_json_file(gav_ts_cg_file_path)

    timestamps = list()
    for gav, ts in gav_ts_cg_file.items():
        if gav.startswith(ga):
            timestamps.append(int(ts))
    
    if not timestamps:
        print(f"Error: {ga} not found in {gav_ts_cg_file_path}")
        return None

    earliest_ts = min(timestamps)
    return earliest_ts


def get_gav_ts(gav):
    global gav_ts_cg_file
    if gav_ts_cg_file is None:
        gav_ts_cg_file = load_json_file(gav_ts_cg_file_path)
    
    if gav not in gav_ts_cg_file:
        print(f"Error: {gav} not found in {gav_ts_cg_file_path}")
        return None
    return int(gav_ts_cg_file[gav])


def gen_package_dep_graph(ga, workdir, ts, filename="filtered_gav_deps_cg.json"):
    visited = set()
    worklist = [ga]

    ga_graph = nx.DiGraph()
    gav_graph = nx.DiGraph()

    while worklist:
        ga = worklist.pop(0)
        ga_earliest_ts = get_earliest_ga_ts(ga)
        if ga_earliest_ts and (ga_earliest_ts > ts):
            # print(f"[*] {ga} is not before {ts}, skipping...")
            continue
        if ga in visited:
            continue
        visited.add(ga)
        # print(f"[*] Processing {ga} (len(worklist)={len(worklist)})")
        g, a = ga.split(":")
        ga_norm = ga.replace(":", "_")

        deps_file = f"{workdir}/{g}/{a}/{filename}"
        if not os.path.exists(deps_file):
            # print(f"[-] {deps_file} does not exist.")
            continue

        deps = load_json_file(deps_file)['deps']
        for ga_dep, gav_deps in deps.items():
            ga_dep_norm = ga_dep.replace(":", "_")
            ga_graph.add_edge(ga_norm, ga_dep_norm)

            # Check for cycles in ga_graph
            if not nx.is_directed_acyclic_graph(ga_graph):
                # raise ValueError(f"Cycle detected in GA graph involving {ga} -> {ga_dep}")
                # remove the edge to break the cycle
                print(f"!!! Cycle detected in GA graph involving {ga} -> {ga_dep}. Removing edge.")
                ga_graph.remove_edge(ga_norm, ga_dep_norm)
                continue

            for up_version, down_versions in gav_deps.items():
                gav_norm = f"{ga_norm}_{up_version}"
                for down_version in down_versions:
                    gav_dep = f"{ga_dep}:{down_version}"
                    down_version_ts = get_gav_ts(gav_dep)
                    if down_version_ts and (down_version_ts > ts):
                        # print(f"[*] {gav_dep} is not before {ts}, skipping...")
                        continue
                    gav_dep_norm = f"{ga_dep_norm}_{down_version}"
                    gav_graph.add_edge(gav_norm, gav_dep_norm)

            # print(f"[*] {ga} -> {ga_dep}")
            worklist.append(ga_dep)

    return ga_graph, gav_graph


def average_path_length_to_leaves(dag, start_node):
    if start_node not in dag:
        raise ValueError(f"{start_node} is not in the graph")

    # Find all leaf nodes (nodes with no outgoing edges)
    leaf_nodes = [node for node in dag.nodes if dag.out_degree(node) == 0]

    # DFS to find path lengths from start_node to all leaf nodes
    path_lengths = []

    def dfs(node, length):
        if node in leaf_nodes:  # Leaf node
            path_lengths.append(length)
            return
        for neighbor in dag.successors(node):
            dfs(neighbor, length + 1)

    dfs(start_node, 0)

    # Calculate average path length
    return sum(path_lengths) / len(path_lengths) if path_lengths else 0


def count_successors_by_prefix(dag, prefix):
    """
    Calculate the number of direct and transitive successors for all nodes starting with the given prefix.

    :param dag: networkx directed graph (DiGraph)
    :param prefix: prefix of node names
    :return: tuple, (number of direct successors, number of transitive successors minus direct)
    """
    result_raw = [0, 0]

    # Iterate all nodes, find those matching the prefix
    for node in dag.nodes:
        if str(node).startswith(prefix):
            # Count direct successors
            direct_successors = set(dag.successors(node))
            direct_count = len(direct_successors)

            # Count transitive successors (using nx.descendants)
            transitive_successors = nx.descendants(dag, node)
            transitive_count = len(transitive_successors)

            # Store results
            result_raw[0] += direct_count
            result_raw[1] += transitive_count - direct_count

    return (result_raw[0], result_raw[1])


def load_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json_file(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def calculate_vpss(cve, ts, index, total_p, total_pv, p_direct, p_transitive, pv_direct, pv_transitive, max_length, avg_length):
    ratio_p_dir = p_direct / total_p
    ratio_p_trans = p_transitive / total_p
    ratio_pv_dir = pv_direct / total_pv
    ratio_pv_trans = pv_transitive / total_pv
    X = [ratio_p_dir, ratio_p_trans, ratio_pv_dir, ratio_pv_trans]

    W_X = sum([W[i] * X[i] for i in range(len(W))])
    pbf = math.log(1 + gamma * W_X)

    pdf = 1 + (max_length + avg_length) / (2 * L_norm)

    vpss_raw = pbf * pdf
    vpss = score_range * (1 - math.exp(-k * vpss_raw))

    return vpss


def get_cve_vpa_stat(cve, timestamp):
    res = dict()
    cve_info = load_cve_info(cve)
    ga = f"{cve_info['groupId']}:{cve_info['artifactId']}"
    ga_norm = ga.replace(":", "_")
    cve_workdir = f"{res_dir}/{cve}"
    ga_graph, gav_graph = gen_package_dep_graph(ga, cve_workdir, timestamp)
    direct_gav, transitive_gav = count_successors_by_prefix(gav_graph, ga_norm)
    if len(ga_graph) != 0:
        direct_deps = list(ga_graph.successors(ga_norm))
        transitives = list(nx.descendants(ga_graph, ga_norm))
    else:
        direct_deps = []
        transitives = []

    res = {
        'ga_dir': len(direct_deps),
        'ga_transitive': len(transitives) - len(direct_deps),
        'gav_dir': direct_gav,
        'gav_transitive': transitive_gav,
    }

    longest_path = nx.dag_longest_path(ga_graph)
    res['longest_path'] = len(longest_path)
    res['longest_path_hops'] = longest_path

    if len(ga_graph) != 0:
        avg_length = average_path_length_to_leaves(ga_graph, ga_norm)
    else:
        avg_length = 0

    res['avg_length'] = avg_length
    return res


def main():
    cve_stat = dict()
    for cve in os.listdir(meta_dir):
        cve = cve.split(".")[0]
        print(f"[*] Processing {cve}...")
        if os.path.exists(f"{output_dir}/{cve}.json"):
            print(f"[*] VPSS stats for {cve} already exists, skipping...")
            continue

        cve_stat[cve] = load_json_file(f"timestamps/eco_stat_cve_monthly/{cve}.json")
        for i, _ in enumerate(cve_stat[cve]):
            ts = cve_stat[cve][i]['ts']
            cve_stat[cve][i]['total_p'] = cve_stat[cve][i]['ga_count']
            cve_stat[cve][i]['total_pv'] = cve_stat[cve][i]['gav_count']
            # remove ga_count and gav_count
            del cve_stat[cve][i]['ga_count']
            del cve_stat[cve][i]['gav_count']

            vpa_stat = get_cve_vpa_stat(cve, ts)
            if vpa_stat:
                cve_stat[cve][i]['p_direct'] = vpa_stat['ga_dir']
                cve_stat[cve][i]['p_transitive'] = vpa_stat['ga_transitive']
                cve_stat[cve][i]['pv_direct'] = vpa_stat['gav_dir']
                cve_stat[cve][i]['pv_transitive'] = vpa_stat['gav_transitive']
                cve_stat[cve][i]['max_length'] = vpa_stat['longest_path']
                cve_stat[cve][i]['avg_length'] = vpa_stat['avg_length']
                cve_stat[cve][i]['vpss'] = calculate_vpss(cve, **cve_stat[cve][i])
                cve_stat[cve][i]['longest_path_hops'] = vpa_stat['longest_path_hops']
            else:
                print(f"[*] {cve} - {ts} ({i}) not found, skipping...")
                continue

        save_json_file(f"{output_dir}/{cve}.json", cve_stat[cve])


if __name__ == "__main__":
    main()
