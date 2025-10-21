import os
import json
import time
import requests
import random
from urllib.parse import quote
import sys


if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <json_file>")
    sys.exit(1)

WORKDIR = "../../workdir"
JSON_FILE = os.path.join(sys.argv[1])
DOWNLOADED_LIST_FILE = os.path.join(WORKDIR, "pom_files.json")
POMS_DIR = os.path.join(WORKDIR, "poms")
MAVEN_REPO_URL = "https://repo1.maven.org/maven2"
DELAY_BETWEEN_REQUESTS = 0.5  # Set download delay (seconds)


def load_downloaded_list():
    if os.path.exists(DOWNLOADED_LIST_FILE):
        with open(DOWNLOADED_LIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def ensure_dir_exists(directory):
    """Ensure directory exists"""
    os.makedirs(directory, exist_ok=True)


def gen_random_user_agent():
    """Generate random User-Agent string"""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.3",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.3",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.3",
    ]
    return random.choice(user_agents)


def gen_random_num():
    """Generate random number between 100 and 200"""
    return random.randint(100, 200)


def load_gav_list(json_file):
    with open(json_file, "r", encoding="utf-8") as f:
        return json.load(f)


def gav_to_pom_url(group_id, artifact_id, version):
    """Generate download URL for pom.xml file based on GAV"""
    group_path = quote(group_id.replace(".", "/"))
    artifact_path = quote(artifact_id)
    version_path = quote(version)
    return f"{MAVEN_REPO_URL}/{group_path}/{artifact_path}/{version_path}/{artifact_path}-{version_path}.pom"


def gav_to_local_path(group_id, artifact_id, version):
    """Generate local save path based on GAV"""
    return os.path.join(
        POMS_DIR, group_id, artifact_id, version, f"{artifact_id}-{version}.pom"
    )


def download_pom(url, local_path):
    """Download pom.xml file and save it locally"""
    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": gen_random_user_agent()})
        response.raise_for_status()  # Check HTTP status code
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "wb") as f:
            f.write(response.content)
        # print(f"[+] Downloaded: {url} -> {local_path}")
    except requests.RequestException as e:
        print(f"[-] Failed to download {url}: {e}")


def main():
    # Ensure directories exist
    ensure_dir_exists(WORKDIR)
    ensure_dir_exists(POMS_DIR)

    # Load downloaded list
    # downloaded_list = load_downloaded_list()

    # Load GAV information
    gav_list = load_gav_list(JSON_FILE)

    # Counter and total count
    total_gavs = 0
    for group in gav_list:
        for artifact in gav_list[group]:
            total_gavs += len(gav_list[group][artifact])

    completed_count = 0

    # Iterate over GAV information and download pom.xml files
    for group_id, artifacts in gav_list.items():
        rand_sleep = gen_random_num()
        for artifact_id, versions in artifacts.items():
            for version in versions:
                local_path = gav_to_local_path(group_id, artifact_id, version)
                if os.path.exists(local_path):
                    completed_count += 1
                    continue
                else:
                    url = gav_to_pom_url(group_id, artifact_id, version)
                    download_pom(url, local_path)
                    time.sleep(DELAY_BETWEEN_REQUESTS)  # Control download rate

                completed_count += 1
                print(f"[*] Progress: {completed_count}/{total_gavs}")
                if completed_count % rand_sleep == 0:
                    print(f"[*] Sleeping for 5 seconds...")
                    time.sleep(5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Bye.")
