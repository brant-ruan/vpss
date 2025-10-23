from neo4j import GraphDatabase
import argparse
from core.config import *
from core.utils import save_to_json


class Neo4jDependencyGraph:
    def __init__(self, uri, user, password):
        """Initialize Neo4j connection"""
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        """Close Neo4j connection"""
        self.driver.close()

    def query_reachable_paths(self, start_ga, depth_limit=None):
        """
        Query all reachable paths from start_ga and store them as a dictionary
        :param start_ga: Starting GA
        :param depth_limit: Limit the maximum query depth (default None, no limit)
        :return: Query results as a dictionary
        """
        with self.driver.session() as session:
            # No longer use `GA` label, applicable to all nodes
            if depth_limit:
                query = f"""
                MATCH path = (n {{name: $start_ga}})-[:RELATED*..{depth_limit}]->(m)
                RETURN path
                """
            else:
                query = """
                MATCH path = (n {name: $start_ga})-[:RELATED*]->(m)
                RETURN path
                """

            # Execute query
            result = session.run(query, start_ga=start_ga)
            paths = []
            for record in result:
                path = record["path"]
                paths.append(self._extract_path_sequence(path))

            # Generate nested dictionary structure
            return self._build_nested_dict(paths)

    def _extract_path_sequence(self, path):
        """
        Parse Neo4j path object and extract GA name sequence
        :param path: Neo4j Path object
        :return: List of GA names (representing the path)
        """
        return [node["name"] for node in path.nodes]

    def _build_nested_dict(self, paths):
        """
        Convert all paths to a nested dictionary structure
        :param paths: List, each element is a path starting from the starting GA
        :return: Nested dictionary
        """
        tree = {}
        for path in paths:
            current_dict = tree
            for node in path:
                if node not in current_dict:
                    current_dict[node] = {}
                current_dict = current_dict[node]
        return tree


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Query all reachable paths from a specified GA in Neo4j")
    parser.add_argument("--ga", type=str, required=True, help="Starting GA node")
    parser.add_argument("--depth", type=int, default=None, help="Maximum query depth (default no limit)")
    parser.add_argument("--output", type=str, required=True, help="Output JSON file path")
    args = parser.parse_args()

    # Connect to Neo4j
    neo4j_graph = Neo4jDependencyGraph(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

    try:
        # Execute query
        print(f"Querying all reachable paths from `{args.ga}`...")
        reachable_paths = neo4j_graph.query_reachable_paths(args.ga, args.depth)

        # Save to JSON file (optimized format)
        output_data = {
            "start_ga": args.ga,
            "dependencies": reachable_paths
        }
        save_to_json(output_data, args.output)

    finally:
        # Close database connection
        neo4j_graph.close()
