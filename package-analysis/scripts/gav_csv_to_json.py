import csv
import json
import argparse
from collections import defaultdict

csv.field_size_limit(10**6)

def csv_to_json(input_csv, output_json):
    gav_structure = defaultdict(lambda: defaultdict(dict))
    with open(input_csv, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            group_id = row['GroupId']
            artifact_id = row['ArtifactId']
            version = row['Version']
            timestamp = row['Timestamp']
            gav_structure[group_id][artifact_id][version] = timestamp

    unique_gav_count = sum(len(versions) for artifacts in gav_structure.values() for versions in artifacts.values())
    print(f"Total unique GAV count: {unique_gav_count}")

    with open(output_json, 'w', encoding='utf-8') as jsonfile:
        json.dump(gav_structure, jsonfile, indent=2, ensure_ascii=False)

    print(f"JSON file has been saved to: {output_json}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Convert GAV CSV to hierarchical JSON")
    parser.add_argument('input_csv', help="Path to the input CSV file")
    parser.add_argument('output_json', help="Path to the output JSON file")
    
    args = parser.parse_args()
    
    csv_to_json(args.input_csv, args.output_json)
