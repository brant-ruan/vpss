import os
import json
import networkx as nx

# Define the path to the deps directory
DEPS_DIR = "../../workdir/kb/deps"
GRAPH_FILE = "../../workdir/ga_dependency_graph.graphml"


def extract_ga(gav: str):
    """Extract GA (group:artifact) from GAV (group:artifact:version)"""
    parts = gav.split(":")
    if len(parts) >= 2:
        return f"{parts[0]}:{parts[1]}"
    return None


def load_dependencies(deps_dir):
    """Traverse the deps directory, parse JSON dependency data, and build GA-level dependency relationships"""
    dependency_graph = nx.DiGraph()

    for root, _, files in os.walk(deps_dir):
        for file in files:
            if file == "dependencies.json":
                print(f"Parsing: {os.path.join(root, file)}")
                json_path = os.path.join(root, file)
                try:
                    with open(json_path, "r") as f:
                        data = json.load(f)

                    for gav, dependencies in data.items():
                        ga = extract_ga(gav)
                        if not ga:
                            continue

                        # Add node with label and name attribute
                        if ga not in dependency_graph:
                            dependency_graph.add_node(ga, label="GA", name=ga) 

                        for dep_gav in dependencies:
                            dep_ga = extract_ga(dep_gav)
                            if dep_ga:
                                # Add node with label and name attribute
                                if dep_ga not in dependency_graph:
                                    dependency_graph.add_node(dep_ga, label="GA", name=dep_ga)
                                # Add edge with relationship type
                                dependency_graph.add_edge(dep_ga, ga, label="DEPENDS_ON")

                except Exception as e:
                    print(f"Failed to parse: {json_path}, error: {e}")

    return dependency_graph


def save_graph(graph, filename):
    """Save the NetworkX dependency graph to a GraphML file"""
    nx.write_graphml(graph, filename)  # FIXED: Ensure GraphML saves attributes
    print(f"Dependency graph saved to: {filename}")


def load_graph(filename):
    """Load the dependency graph from a GraphML file"""
    return nx.read_graphml(filename)


if __name__ == "__main__":
    print("Starting to parse the `deps` directory and build the dependency graph...")
    # first check if the dependency graph already exists
    if os.path.exists(GRAPH_FILE):
        print(f"Dependency graph already exists at: {GRAPH_FILE}")
        graph = load_graph(GRAPH_FILE)
    else:
        graph = load_dependencies(DEPS_DIR)
        save_graph(graph, GRAPH_FILE)

    print(f"Num of nodes: {graph.number_of_nodes()}")
    print(f"Num of edges: {graph.number_of_edges()}")
