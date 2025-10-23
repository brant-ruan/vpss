import json
import requests
import os
import sys
import random
from difflib import SequenceMatcher

from core.config import *
import subprocess


proxy_lists = [
    None, # self
]

def get_proxy_from_file():
    global proxy_lists
    if proxy_lists:
        return random.choice(proxy_lists)


def download_gav_jar(gav):
    # gav example: com.textrecruit.ustack:textrecruit-ustack-core:1.0.6
    # url example: https://repo1.maven.org/maven2/com/textrecruit/ustack/textrecruit-ustack-core/1.0.6/textrecruit-ustack-core-1.0.6.jar
    g, a, v = gav.split(":")
    jar_file = f"{JAR_DIR}/{g}/{a}/{v}/{a}-{v}.jar"
    ensure_dir(f"{JAR_DIR}/{g}/{a}/{v}")
    jar_url = f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.jar"
    status = download_file(jar_url, jar_file)
    # if jar file is not found, try with .war
    if not status:
        # print(f"[-] .jar not found. Trying with .war file.")
        war_file = f"{JAR_DIR}/{g}/{a}/{v}/{a}-{v}.war"
        war_url = f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.war"
        status = download_file(war_url, war_file)
        if status is None:
            print(f"[-] .jar and .war not found.")
            return None
        if status is False:
            print(f"[!] Failed to download <{war_url}>")
            return False
        # if war file is found, convert it to jar
        # unzip the war file into f"{JAR_DIR}/{g}/{a}/{v}/war_extracted"
        ensure_dir(f"{JAR_DIR}/{g}/{a}/{v}/war_extracted")
        try:
            subprocess.run(
            ["unzip", "-o", "-q", war_file, "-d", f"{JAR_DIR}/{g}/{a}/{v}/war_extracted"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to unzip {war_file}: {e}")
        # cd war_extracted/WEB-INF/classes/ and jar cvf {jar_file} *
        try:
            subprocess.run(
            [
            "jar", "cvf", f"{JAR_DIR}/{g}/{a}/{v}/{a}-{v}.jar", "-C",
            f"{JAR_DIR}/{g}/{a}/{v}/war_extracted/WEB-INF/classes", "."
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to create jar file from war contents: {e}")
            jar_file = None
        # remove war_extracted
        os.system(f"rm -rf {JAR_DIR}/{g}/{a}/{v}/war_extracted")
        # remove war file
        os.system(f"rm {war_file}")
    
        return jar_file
    else:
        return status


def load_cve_info(cve_id):
    cve_path = f"{CVE_DATASET_DIR}/{cve_id}.json"
    if not os.path.exists(cve_path):
        print(f"[-] Error: {cve_path} does not exist.")
        sys.exit(1)
    
    cve_info = load_from_json(cve_path)
    return cve_info


def save_to_json(data, output_file, indent=2):
    """Save query results as a JSON file"""
    with open(output_file, "w", encoding="utf-8") as f:
        if indent is None:
            json.dump(data, f, ensure_ascii=False)
        else:
            json.dump(data, f, indent=indent, ensure_ascii=False)


def load_from_json(file_path):
    """Load JSON file"""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def download_file(url, output_file):
    from filelock import FileLock, Timeout
    import os

    lock_path = f"{output_file}.lock"
    lock = FileLock(lock_path)

    try:
        with lock.acquire(timeout=600):
            if os.path.exists(output_file):
                return output_file

            print(f"[*] Downloading <{url}>")

            proxies = get_proxy_from_file()
            print(f"[*] Using proxy: {proxies}")

            try:
                response = requests.get(url, proxies=proxies, timeout=20)
            except Exception as e:
                print(f"[!] Proxy download error: {e}")
                return False

            if response.status_code == 404:
                return None
            if response.status_code != 200:
                print(f"[!] Failed to download <{url}>: {response.status_code}")
                print(response.text)
                return False

            with open(output_file, "wb") as f:
                f.write(response.content)

            print(f"[+] Downloaded <{url}>")
            return output_file
    except Timeout:
        print(f"[!] Timeout acquiring lock for {output_file}")
        return False


def ensure_dir(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)


def calculate_similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()
