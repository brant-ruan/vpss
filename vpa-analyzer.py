#!/usr/bin/env python3

import sqlite3
import json
import sys
import zipfile
import os
from filelock import FileLock
import subprocess
import tempfile
import shutil
import argparse
import multiprocessing
import networkx as nx
from collections import deque
from core.config import *
from core.utils import *
from core.package_analysis import Neo4jDependencyGraph


def get_pom_deps(gav):
    deps_json = f"{GLOBAL_DEPS_DIR}/{gav.replace(':', '/')}/dependencies.json"
    if os.path.exists(deps_json):
        deps_data = load_from_json(deps_json)
        return deps_data

    return None


def gen_ga_deps(ga, workdir, depth=1):
    print(f"[*] Finding GA deps for <{ga}>")
    neo4j_graph = Neo4jDependencyGraph(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    g, a = ga.split(":")
    file_path = f"{workdir}/{g}/{a}/ga-deps.json"
    if os.path.exists(file_path):
        deps_data = load_from_json(file_path)
        print(f"[+] {len(deps_data['deps'])} GA deps found at <{file_path}>")
        return file_path

    reachable_paths = neo4j_graph.query_reachable_paths(ga, depth_limit=depth)
    output_data = {
            "ga": ga,
            "deps": reachable_paths.get(ga, dict())
    }
    save_to_json(output_data, file_path)
    print(f"[+] {len(output_data['deps'])} deps saved to <{file_path}>")
    return file_path


def get_gav_dep_list(ga_up, ga_down, up_versions):
    gav_up_list = [f"{ga_up}:{v}" for v in up_versions]
    gav_dep_version_mappings = dict()
    ga_down_dep_dir = f"{GLOBAL_DEPS_DIR}/{ga_down.replace(':', '/')}"
    # print(f"[*] Checking for <{ga_down}> in {ga_down_dep_dir}")
    # for each dir (version) in ga_down_dep_dir
    for version in os.listdir(ga_down_dep_dir):
        dep_data = load_from_json(f"{ga_down_dep_dir}/{version}/dependencies.json")
        gav_down = f"{ga_down}:{version}"
        deps = dep_data[gav_down]
        for dep in deps:
            if dep in gav_up_list:
                v_up = dep.split(":")[-1]
                if v_up not in gav_dep_version_mappings:
                    gav_dep_version_mappings[v_up] = [version]
                else:
                    gav_dep_version_mappings[v_up].append(version)
                break
    return gav_dep_version_mappings


def gen_gav_deps(ga, vuln_versions, workdir):
    print(f"[*] Generating and filtering version deps for <{ga}>")
    g, a = ga.split(":")
    file_path = f"{workdir}/{g}/{a}/gav_deps.json"
    changed = False
    if os.path.exists(file_path):
        gav_deps = load_from_json(file_path)
        print(f"[+] {len(gav_deps['deps'].keys())} GA's GAV deps found at <{file_path}>")
    else:
        changed = True
        gav_deps = {'ga': ga, 'deps': dict()}
 
    dep_data = load_from_json(f"{workdir}/{g}/{a}/ga-deps.json")
    ga_deps = dep_data["deps"].keys()
    delta = {'deps': dict(), 'ga': ga}
    for dep in ga_deps:
        gav_dep_version_mappings = get_gav_dep_list(ga, dep, vuln_versions)
        if gav_dep_version_mappings:
            delta['deps'][dep] = gav_dep_version_mappings
            if not dep in gav_deps['deps'].keys():
                changed = True
                gav_deps['deps'][dep] = gav_dep_version_mappings
            else:
                for v_up, v_downs in gav_dep_version_mappings.items():
                    if v_up not in gav_deps['deps'][dep].keys():
                        changed = True
                        gav_deps['deps'][dep][v_up] = v_downs
                    else:
                        for v_down in v_downs:
                            if v_down not in gav_deps['deps'][dep][v_up]:
                                changed = True
                                gav_deps['deps'][dep][v_up].append(v_down)
        else:
            # print(f"[!] No matching versions found for <{dep}> (filtered)")
            continue
    
    save_to_json(gav_deps, f"{workdir}/{g}/{a}/gav_deps.json")
    if changed:
        print(f"[+] GAV deps of {len(gav_deps['deps'])} GAs saved to <{file_path}> (changed)")
    return changed, delta


def get_packages_from_jar_new(jar_path):
    if not os.path.exists(jar_path):
        print(f"[!] File not found: {jar_path}")
        return set()

    class_names = set()
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # continue even if unzip returns non-zero
            result = subprocess.run(["unzip", "-o", "-q", jar_path, "-d", tmpdir], check=False)

            # check if .class files are present
            found_class = False
            for root, _, files in os.walk(tmpdir):
                for file in files:
                    if file.endswith(".class") and "META-INF" not in root:
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, tmpdir)
                        class_name = rel_path[:-6].replace('/', '.').replace('\\', '.')
                        class_names.add(class_name)
                        found_class = True

            if not found_class:
                print(f"[!] No class files found in {jar_path}")
            elif result.returncode != 0:
                print(f"[!] unzip returned non-zero for {jar_path}, but class files were extracted. Continuing...")

            return sorted(class_names)
        except Exception as e:
            print(f"[!] Failed to extract packages from {jar_path}: {e}")
            return set()


def get_gav_package_prefix(gav, jar_file, similarity_threshold=0.5):  # deprecated
    candidates = get_packages_from_jar_new(jar_file)
    if not candidates:
        return None
    # find the longest common prefix (we need to strip dot at the end)
    prefix = os.path.commonprefix(candidates).strip(".")
    if prefix:
        return prefix

    g, a, _ = gav.split(":")
    ga = f"{g}:{a}"
    ga_norm = ga.replace('-', '.').replace(':', '.')
    scored_packages = list()

    for package in candidates:
        similarity = calculate_similarity(package, ga_norm)
        scored_packages.append((package, similarity))
        
    # filter out the packages with similarity lower than the threshold
    jar_packages = [pkg for pkg, score in scored_packages if score >= similarity_threshold]
    # also check whether the G is in the jar packages
    jar_packages_grp = [pkg for pkg in jar_packages if g in pkg]
    if jar_packages_grp:
        jar_packages = jar_packages_grp
    
    # return os.path.commonprefix(jar_packages).strip(".")
    return jar_packages


def query_gav_package_prefix_db(gav, db_path=GAV_PREFIX_DB):
    g, a, v = gav.split(":")
    conn = sqlite3.connect(db_path, timeout=30)
    c = conn.cursor()
    c.execute('''
        SELECT package_prefixes FROM gav_package_prefix
        WHERE group_id=? AND artifact_id=? AND version=?
    ''', (g, a, v))
    result = c.fetchone()
    conn.close()
    if result:
        return json.loads(result[0])
    # print(f"[-] GAV packages of <{gav}> not found in <{db_path}>")
    return None


def update_gav_package_prefix_db(gav, packages, db_path=GAV_PREFIX_DB):
    g, a, v = gav.split(":")
    conn = sqlite3.connect(db_path, timeout=30)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO gav_package_prefix
        (group_id, artifact_id, version, package_prefixes)
        VALUES (?, ?, ?, ?)
    ''', (g, a, v, json.dumps(packages)))
    conn.commit()
    conn.close()
    # print(f"[*] Updated GAV packages of <{gav}> in <{db_path}>")


def is_valid_gav(gav):
    # check the version format
    g, a, v = gav.split(":")
    if ',' in v or '[' in v:
        return False
    return True


def get_gav_package_prefix_new(gav, jar_file):
    packages = query_gav_package_prefix_db(gav)
    if packages:
        return packages

    candidates = get_packages_from_jar_new(jar_file)

    pom_deps = get_pom_deps(gav)
    if not pom_deps:
        print(f"[-] POM deps not found for <{gav}>")
        print("[!] Using all classes from the jar file as candidates")
        return candidates

    for pom_dep in pom_deps[gav]:
        if not is_valid_gav(pom_dep):
            print(f"[-] Invalid POM dependency <{pom_dep}> for <{gav}>")
            continue
        dep_jar_file = download_gav_jar(pom_dep)
        if not dep_jar_file:
            print(f"[-] Failed to download pom_dep <{pom_dep}> for <{gav}>")
            continue
        pom_dep_candidates = get_packages_from_jar_new(dep_jar_file)
        for pom_dep_package in pom_dep_candidates:
            try:
                candidates.remove(pom_dep_package)
            except ValueError:
                pass
    update_gav_package_prefix_db(gav, candidates)
    return candidates


def strip_module_info(jar_file):
    try:
        list_output = subprocess.check_output(["unzip", "-l", jar_file], stderr=subprocess.DEVNULL).decode()
        if "module-info.class" not in list_output:
            return jar_file 

        print(f"[*] Stripping module-info.class from <{jar_file}>")

        tmpdir = tempfile.mkdtemp()

        extracted_dir = os.path.join(tmpdir, "extracted")
        os.makedirs(extracted_dir, exist_ok=True)

        subprocess.run(["unzip", "-o", "-q", jar_file, "-d", extracted_dir], check=False)

        for root, dirs, files in os.walk(extracted_dir):
            for file in files:
                if file == "module-info.class":
                    os.remove(os.path.join(root, file))

        stripped_jar_path = os.path.join(tmpdir, "stripped.jar")
        subprocess.run(["jar", "cf", stripped_jar_path, "-C", extracted_dir, "."], check=True)

        return stripped_jar_path
    except Exception as e:
        print(f"[!] Error processing {jar_file}: {e}")
        return jar_file


def repack_jar_overwrite(jar_path):
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            with zipfile.ZipFile(jar_path, 'r') as zin:
                zin.extractall(tmpdir)
            fixed_zip = os.path.join(tmpdir, "fixed.zip")
            shutil.make_archive(fixed_zip.replace(".zip", ""), 'zip', tmpdir)
            fixed_jar = fixed_zip.replace(".zip", ".jar")
            os.rename(fixed_zip, fixed_jar)
            shutil.move(fixed_jar, jar_path) 
            print(f"[+] Repacked and replaced corrupted JAR: {jar_path}")
            return jar_path
        except Exception as e:
            print(f"[!] Failed to repack and overwrite JAR: {e}")
            return None


def check_package_prefix_deps(ga_up_package_prefix, ga_down_package_prefix, jar_file):
    def run_jdeps(target_jar):
        cmd = f"jdeps --multi-release base -verbose:{JDEPS_VERBOSE_LEVEL} {target_jar}"
        jar_size = os.path.getsize(target_jar) / (1024 * 1024)
        cmd_timeout = 1.6 * jar_size + 10
        try:
            output = subprocess.check_output(cmd, shell=True, timeout=cmd_timeout, stderr=subprocess.STDOUT).decode("utf-8")
            return True, output
        except subprocess.CalledProcessError as e:
            return False, e.output.decode("utf-8", errors="ignore")
        except subprocess.TimeoutExpired:
            print(f"[-] jdeps command timed out for {target_jar}")
            return False, ""

    def is_class_in_prefix(class_name, package_prefixes):
        return any(class_name.startswith(prefix) for prefix in package_prefixes)

    cleaned_jar = strip_module_info(jar_file)
    temp_dir = os.path.dirname(cleaned_jar)
    success, output = run_jdeps(cleaned_jar)

    if not success:
        if "Invalid CEN header" in output or "ZipException" in output:
            print(f"[!] Detected zip corruption in {jar_file}, trying to repack...")
            fixed_jar = repack_jar_overwrite(jar_file)
            if fixed_jar:
                success, output = run_jdeps(fixed_jar)
            else:
                print(f"[!] Repacking failed, skipping {jar_file}")
                # remove the temp dir
                shutil.rmtree(temp_dir, ignore_errors=True)
                return True  

    if cleaned_jar != jar_file and os.path.exists(cleaned_jar):
        # remove not only the cleaned_jar, but also the whole temp dir
        shutil.rmtree(temp_dir, ignore_errors=True)


    if not success:
        print(f"[!] jdeps still failed on {jar_file}")
        return True

    for line in output.splitlines():
        line  = line.strip()
        parts = line.split("->")
        if len(parts) != 2:
            continue
        down_class = parts[0].strip()
        up_class = parts[1].strip().split()[0]
        if is_class_in_prefix(down_class, ga_down_package_prefix):
            if is_class_in_prefix(up_class, ga_up_package_prefix):
                return True

    return False


def update_reflection_status_in_db(gav, reflection_status, db_path=GAV_PREFIX_DB):
    g, a, v = gav.split(":")
    conn = sqlite3.connect(db_path, timeout=30)
    c = conn.cursor()
    c.execute('''
        UPDATE gav_package_prefix
        SET reflection = ?
        WHERE group_id = ? AND artifact_id = ? AND version = ?
    ''', (reflection_status, g, a, v))
    conn.commit()
    conn.close()


def query_reflection_status_from_db(gav, db_path=GAV_PREFIX_DB):
    g, a, v = gav.split(":")
    conn = sqlite3.connect(db_path, timeout=30)
    c = conn.cursor()
    c.execute('''
        SELECT reflection FROM gav_package_prefix
        WHERE group_id = ? AND artifact_id = ? AND version = ?
    ''', (g, a, v))
    result = c.fetchone()
    conn.close()
    if result is not None:
        return result[0]
    return None


def check_reflection_calls(package_prefix, jar_file, gav=None):
    if gav:
        reflection_status = query_reflection_status_from_db(gav)
        if reflection_status is not None and reflection_status != -1:
            return reflection_status == 1

    reflection_method_list_file = f"{ANNOTATIONS_DIR}/reflection_methods.json"
    cmd = f"java -jar prog-analysis/target/prog-analysis-1.0.jar --task check-reflect --jar-path {jar_file} --method-list {reflection_method_list_file}"
    if package_prefix:
        # now package_prefix is a list of package names
        # save it into a temp file and pass it to the prog-analysis tool
        package_prefix_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        for prefix in package_prefix:
            package_prefix_file.write(prefix + "\n")
        package_prefix_file.close()
        cmd += f" --package-prefix {package_prefix_file.name}"
    
    try:
        output = subprocess.check_output(cmd, shell=True).decode("utf-8")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        if package_prefix:
            if os.path.exists(package_prefix_file.name):
                os.unlink(package_prefix_file.name)
    
    # parse the output as json
    try:
        output_json = json.loads(output)
        found_reflection = output_json['foundReflection']
        if gav:
            update_reflection_status_in_db(gav, 1 if found_reflection else 0)
        return found_reflection
    except json.JSONDecodeError:
        print(f"[-] Failed to parse JSON output from prog-analysis: {output}")
        if gav:
            update_reflection_status_in_db(gav, -1)
        return False


def process_dependency(args):
    ga_up_package_prefix, ga_up, ga_down, v_up, v_down, workdir = args
    g_up, a_up = ga_up.split(":")
    g_down, a_down = ga_down.split(":")

    if os.path.exists(f"{workdir}/{g_up}/{a_up}/selected/{v_up}/{g_down}/{a_down}/{v_down}"):
        return (True, v_down, True)    
    gav_down = f"{ga_down}:{v_down}"
    jar_file = download_gav_jar(gav_down)
    if jar_file == None:
        return (ga_down, v_down, None)
    if jar_file == False:
        return (ga_down, v_down, STATUS_NETWORK_ERROR)

    ga_down_package_prefix = get_gav_package_prefix_new(gav_down, jar_file)

    # check if the jar file includes essential reflective calls
    # if so, we need to bypass the check_package_prefix_deps
    if CG_GENERATOR == CG_GENERATOR_TAIE:
        status = check_reflection_calls(ga_down_package_prefix, jar_file, gav_down)
        if status:
            print(f"[+] Found reflection calls in <{gav_down}> (jdeps check skipped)")
            return (ga_down, v_down, True)

    status = check_package_prefix_deps(ga_up_package_prefix, ga_down_package_prefix, jar_file)
    if status:
        return (ga_down, v_down, True)
    if status is None:
        print(f"[-] Failed to check package prefix for <{gav_down}>")
    return (ga_down, v_down, False)


def filter_gav_deps(ga, gav_deps, workdir, proc_num=40):
    g, a = ga.split(":")
    filtered_file_path = f"{workdir}/{g}/{a}/filtered_gav_deps.json"
    print(f"[*] Filtering GAV deps for <{filtered_file_path}> (jdeps)")

    if os.path.exists(filtered_file_path):
        old_gav_deps = load_from_json(filtered_file_path)
        print(f"[+] {len(old_gav_deps['deps'])} GA's GAV deps found at <{filtered_file_path}>")
    else:
        old_gav_deps = {'ga': ga, 'deps': dict()}
    
    # create selected directories
    # and we use them as the cache for the filtering process
    ensure_dir(f"{workdir}/{g}/{a}/selected")

    ga_up = gav_deps['ga']
    deps = gav_deps['deps']
    ga_up_package_prefix = None

    filtered_deps = dict()
    pool = multiprocessing.Pool(processes=proc_num)

    cnt = 0
    filtered_cnt = 0
    len_deps = len(deps)
    for ga_down, version_mappings in deps.items():
        cnt += 1
        print(f"[*] {cnt}/{len_deps} Filtering <{ga_down}>")
        filtered_deps[ga_down] = dict()
        for v_up, v_downs in version_mappings.items():
            filtered_deps[ga_down][v_up] = list()
            if not ga_up_package_prefix:
                gav_up = f"{ga_up}:{v_up}"
                jar_file = download_gav_jar(gav_up)
                ga_up_package_prefix = get_gav_package_prefix_new(gav_up, jar_file)
                if not ga_up_package_prefix:
                    print(f"[-] Failed to find GA package prefix for <{ga_up}>")
                    continue

            tasks = [(ga_up_package_prefix, ga_up, ga_down, v_up, v_down, workdir) for v_down in v_downs]
            results = pool.map(process_dependency, tasks)

            for res_ga_down, res_v_down, res_status in results:
                if not res_ga_down:
                    continue
                if res_ga_down is True:
                    filtered_deps[ga_down][v_up].append(res_v_down)
                    continue
                if res_status == STATUS_NETWORK_ERROR:
                    # just skip this gav, so that we can retry later
                    continue
                if res_status is True:
                    filtered_deps[ga_down][v_up].append(res_v_down)
                    ensure_dir(f"{workdir}/{g}/{a}/selected/{v_up}/{ga_down.replace(':', '/')}/{res_v_down}")
                # else:
                    # ensure_dir(f"{workdir}/{g}/{a}/filtered/{v_up}/{ga_down.replace(':', '/')}/{res_v_down}")

        # if for all v_up, v_downs is empty, remove ga_down
        if not any(filtered_deps[ga_down].values()):
            filtered_cnt += 1
            print(f"[!] {filtered_cnt}/{len_deps} <{ga_down}> does not depend on <{ga_up}> (jdeps filtered)")
            filtered_deps.pop(ga_down)

    pool.close()
    pool.join()

    changed = False

    new_gav_deps = {
        "ga": ga_up,
        "deps": filtered_deps
    }
    for dep in new_gav_deps['deps']:
        if dep not in old_gav_deps['deps']:
            changed = True
            old_gav_deps['deps'][dep] = new_gav_deps['deps'][dep]
        else:
            for v_up in new_gav_deps['deps'][dep]:
                if v_up not in old_gav_deps['deps'][dep]:
                    changed = True
                    old_gav_deps['deps'][dep][v_up] = new_gav_deps['deps'][dep][v_up]
                else:
                    for v_down in new_gav_deps['deps'][dep][v_up]:
                        if v_down not in old_gav_deps['deps'][dep][v_up]:
                            changed = True
                            old_gav_deps['deps'][dep][v_up].append(v_down)
        
    if changed:
        print(f"[+] {len(old_gav_deps['deps'])} GA's GAV deps saved to <{filtered_file_path}> (changed)")
    save_to_json(old_gav_deps, f"{filtered_file_path}")
    return changed, new_gav_deps


def process_dependency_cg(args):
    cve, entrypoints, ga_up, ga_down, v_up, v_down, workdir = args
    g_up, a_up = ga_up.split(":")
    g_down, a_down = ga_down.split(":")
    # if os.path.exists(f"{workdir}/{g_up}/{a_up}/filtered_cg/{v_up}/{g_down}/{a_down}/{v_down}"):
    #     return (ga_down, v_up, v_down, False, None)
    if os.path.exists(f"{workdir}/{g_up}/{a_up}/selected_cg/{v_up}/{g_down}/{a_down}/{v_down}"):
        # read the callers from {workdir}/{g_up}/{a_up}/selected_cg/{v_up}/{g_down}/{a_down}/{v_down}/callers.json
        callers_file = f"{workdir}/{g_up}/{a_up}/selected_cg/{v_up}/{g_down}/{a_down}/{v_down}/callers.json"
        callers = load_from_json(callers_file)
        return (ga_down, v_up, v_down, True, callers)

    gav_down_jar_file = f"{JAR_DIR}/{g_down}/{a_down}/{v_down}/{a_down}-{v_down}.jar"
    gav_prefix = get_gav_package_prefix_new(f"{ga_down}:{v_down}", gav_down_jar_file)

    status = False  # by default, we use Soot, so we do not need to check the reflection calls
    if CG_GENERATOR == CG_GENERATOR_TAIE:
    # check if the jar file includes essential reflective calls
        status = check_reflection_calls(gav_prefix, gav_down_jar_file, f"{ga_down}:{v_down}")
    if status:
        print(f"[+] Found reflection calls in <{ga_down}:{v_down}> (quick caller-callee check skipped)")
    else:
        # quickly check whether the entrypoints are called in the target jar on bytecode-level
        print(f"[*] Quickly checking whether EPs of <{ga_up}:{v_up}> are called in <{ga_down}:{v_down}>")
        # save the entrypoints into a temp txt file, which can be used and deleted after the check
        # create a temp file with python tempfile module and we need the filename
        entrypoints_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        for entrypoint in entrypoints:
            entrypoints_file.write(entrypoint + "\n")
        entrypoints_file.close()
        cmd = f"java -jar prog-analysis/target/prog-analysis-1.0.jar --task check-call --jar-path {gav_down_jar_file} -m {entrypoints_file.name}"

        if gav_prefix:
            # now package_prefix is a list of package names
            # save it into a temp file and pass it to the prog-analysis tool
            package_prefix_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
            for prefix in gav_prefix:
                package_prefix_file.write(prefix + "\n")
            package_prefix_file.close()
            cmd += f" --package-prefix {package_prefix_file.name}"

        # the check will print YES or NO, so we need to capture the output and check
        try:
            output = subprocess.check_output(cmd, shell=True).decode("utf-8")
        except subprocess.CalledProcessError as e:
            print(f"[-] Error: {e}")
            return (ga_down, v_up, v_down, False, None)
        finally:
            os.unlink(entrypoints_file.name)
            if gav_prefix:
                if os.path.exists(package_prefix_file.name):
                    os.unlink(package_prefix_file.name)

        if "NO" in output:
            return (ga_down, v_up, v_down, False, None)

        print(f"[+] EPs of <{ga_up}:{v_up}> are called in <{ga_down}:{v_down}>")

    gav_down_cg_file = gen_gav_cg(f"{ga_down}:{v_down}", gav_prefix, cve)
    if not gav_down_cg_file:
        print(f"[-] Failed to generate CG for <{ga_down}:{v_down}>")
        return (ga_down, v_up, v_down, False, None)

    callers = get_down_callers(entrypoints, gav_down_cg_file)
    if callers:
        return (ga_down, v_up, v_down, True, callers)
    return (ga_down, v_up, v_down, False, None)


def filter_gav_deps_cg(cve, ga, sink_funcs, filtered_gav_deps, workdir, proc_num=40):
    changed = False

    g, a = ga.split(":")
    filtered_file_path_cg = f"{workdir}/{g}/{a}/filtered_gav_deps_cg.json"
    print(f"[*] Filtering GAV deps for <{filtered_file_path_cg}> (CG-level)")
    if os.path.exists(filtered_file_path_cg):
        old_gav_deps = load_from_json(filtered_file_path_cg)
        print(f"[+] CG-level {len(old_gav_deps['deps'])} GA's GAV deps found at <{filtered_file_path_cg}>")
    else:
        old_gav_deps = {'ga': ga, 'deps': dict()}

    # create filtered and selected directories
    # and we use them as the cache for the filtering process
    ensure_dir(f"{workdir}/{g}/{a}/selected_cg")

    ga_up = filtered_gav_deps['ga']
    deps = filtered_gav_deps['deps']
    filtered_deps_cg = dict()
    calls = dict()

    calls_json = f"{workdir}/{g}/{a}/dep_calls.json"
    if os.path.exists(calls_json):
        cg_calls = load_from_json(calls_json)
    else:
        cg_calls = {'ga': ga, 'calls': dict()}

    pool = multiprocessing.Pool(processes=proc_num)

    cnt = 0
    filtered_cnt = 0
    len_deps = len(deps)
    for ga_down, version_mappings in deps.items():
        cnt += 1
        print(f"[*] {cnt}/{len_deps} CG-level filtering <{ga_down}>")
        filtered_deps_cg[ga_down] = dict()
        calls[ga_down] = dict()
        for v_up, v_downs in version_mappings.items():
            filtered_deps_cg[ga_down][v_up] = list()
            calls[ga_down][v_up] = dict()
            gav_package_prefix = get_gav_package_prefix_new(f"{ga_up}:{v_up}", download_gav_jar(f"{ga_up}:{v_up}"))
            gav_up_cg = gen_gav_cg(f"{ga_up}:{v_up}", gav_package_prefix, cve)
            if not gav_up_cg:
                print(f"[-] Failed to generate CG for <{ga_up}:{v_up}>")
                continue

            entrypoints = get_entry_points(sink_funcs[v_up], gav_up_cg)
            print(f"[+] Found {len(entrypoints)} entrypoints for <{gav_up_cg}>")
            if not entrypoints:  # if no entrypoints are found, skip the filtering
                # for v_down in v_downs:
                #     ensure_dir(f"{workdir}/{g}/{a}/filtered_cg/{v_up}/{ga_down.replace(':', '/')}/{v_down}")
                continue
            tasks = [(cve, entrypoints, ga_up, ga_down, v_up, v_down, workdir) for v_down in v_downs]
            results = pool.map(process_dependency_cg, tasks)

            for res_ga_down, res_v_up, res_v_down, res_status, res_callers in results:
                if res_status:
                    filtered_deps_cg[res_ga_down][res_v_up].append(res_v_down)
                    calls[res_ga_down][res_v_up][res_v_down] = res_callers
                    ensure_dir(f"{workdir}/{g}/{a}/selected_cg/{res_v_up}/{res_ga_down.replace(':', '/')}/{res_v_down}")
                    # if {workdir}/{g}/{a}/selected_cg/{res_v_up}/{res_ga_down.replace(':', '/')}/{res_v_down}/callers.json does not exist
                    # save the callers to the file
                    if os.path.exists(f"{workdir}/{g}/{a}/selected_cg/{res_v_up}/{res_ga_down.replace(':', '/')}/{res_v_down}/callers.json"):
                        # load the existing callers and merge them
                        existing_callers = load_from_json(f"{workdir}/{g}/{a}/selected_cg/{res_v_up}/{res_ga_down.replace(':', '/')}/{res_v_down}/callers.json")
                    else:
                        existing_callers = dict()
                    # merge the callers
                    for entrypoint in res_callers:
                        if entrypoint not in existing_callers:
                            existing_callers[entrypoint] = res_callers[entrypoint]
                        else:
                            existing_callers[entrypoint].extend(res_callers[entrypoint])
                            existing_callers[entrypoint] = list(set(existing_callers[entrypoint]))
                    save_to_json(existing_callers, f"{workdir}/{g}/{a}/selected_cg/{res_v_up}/{res_ga_down.replace(':', '/')}/{res_v_down}/callers.json")

        # if for all v_up, v_downs is empty, remove ga_down
        if not any(filtered_deps_cg[ga_down].values()):
            filtered_cnt += 1
            print(f"[!] {filtered_cnt}/{len_deps} <{ga_down}> does not depend on <{ga_up}> (CG-level filtered)")
            filtered_deps_cg.pop(ga_down)
            calls.pop(ga_down)
        else:
            changed = True

    pool.close()
    pool.join()


    new_gav_deps_cg = {
        "ga": ga_up,
        "deps": filtered_deps_cg,
    }

    for dep in new_gav_deps_cg['deps']:
        if dep not in old_gav_deps['deps']:
            old_gav_deps['deps'][dep] = new_gav_deps_cg['deps'][dep]
        else:
            for v_up in new_gav_deps_cg['deps'][dep]:
                if v_up not in old_gav_deps['deps'][dep]:
                    old_gav_deps['deps'][dep][v_up] = new_gav_deps_cg['deps'][dep][v_up]
                else:
                    for v_down in new_gav_deps_cg['deps'][dep][v_up]:
                        if v_down not in old_gav_deps['deps'][dep][v_up]:
                            old_gav_deps['deps'][dep][v_up].append(v_down)

    for dep in calls:
        if dep not in cg_calls['calls']:
            cg_calls['calls'][dep] = calls[dep]
        else:
            for v_up in calls[dep]:
                if v_up not in cg_calls['calls'][dep]:
                    cg_calls['calls'][dep][v_up] = calls[dep][v_up]
                else:
                    for v_down in calls[dep][v_up]:
                        if v_down not in cg_calls['calls'][dep][v_up]:
                            cg_calls['calls'][dep][v_up][v_down] = calls[dep][v_up][v_down]
                        else:
                            for ee in calls[dep][v_up][v_down]:
                                if ee not in cg_calls['calls'][dep][v_up][v_down]:
                                    cg_calls['calls'][dep][v_up][v_down][ee] = calls[dep][v_up][v_down][ee]
                                else:
                                    cg_calls['calls'][dep][v_up][v_down][ee].extend(calls[dep][v_up][v_down][ee])
                                    cg_calls['calls'][dep][v_up][v_down][ee] = list(set(cg_calls['calls'][dep][v_up][v_down][ee]))

    if changed:
        print(f"[+] {len(old_gav_deps['deps'])} GA's GAV deps saved to <{filtered_file_path_cg}> (changed)")

    save_to_json(old_gav_deps, f"{filtered_file_path_cg}")
    # save_to_json(new_gav_deps_cg, f"{workdir}/{g}/{a}/filtered_gav_deps_cg.json")
    save_to_json(cg_calls, f"{workdir}/{g}/{a}/dep_calls.json")
    print(f"[+] {len(new_gav_deps_cg['deps'])} GA's GAV deps saved to <{filtered_file_path_cg}> (CG-level)")

    return changed, new_gav_deps_cg


def filter_cg(cg_file, package_prefix):
    with open(cg_file, 'r') as f:
        data = json.load(f)

    G = nx.DiGraph()
    for node in data['nodes']:
        G.add_node(node['signature'], modifier=node.get('modifier', ''))

    for edge in data['edges']:
        G.add_edge(edge['src'], edge['tgt'])

    def is_valid_src(signature):
        for prefix in package_prefix:
            if signature.startswith('<' + prefix):  # e.g., <com.example.MyClass: ...
                return True
        return False

    H = nx.DiGraph()
    for u, v in G.edges():
        if is_valid_src(u):
            H.add_edge(u, v)

    for node in H.nodes():
        if node in G.nodes:
            H.nodes[node]['modifier'] = G.nodes[node].get('modifier', '')

    new_nodes = [{'signature': n, 'modifier': H.nodes[n].get('modifier', '')} for n in H.nodes()]
    new_edges = [{'src': u, 'tgt': v} for u, v in H.edges()]

    output_data = {
        'nodes': new_nodes,
        'edges': new_edges
    }

    with open(cg_file, 'w') as f:
        json.dump(output_data, f, indent=2)


def gen_gav_cg(gav, package_prefix, cve_id=None):
    print(f"[*] Generating callgraph for <{gav}> with {CG_GENERATOR}")
    cg_file = f"{CALLGRAPH_DIR}/{gav.replace(':', '/')}/cg.json"
    lock_file = cg_file + ".lock"
    lock = FileLock(lock_file)
    with lock.acquire(timeout=600):
        if os.path.exists(cg_file):
            return cg_file
        
        jar_file = download_gav_jar(gav)  # normally, the jar file should already exist

        # before this step, the prog-analysis tool should be built
        ensure_dir(f"{CALLGRAPH_DIR}/{gav.replace(':', '/')}")

        if package_prefix:
            # now package_prefix is a list of package names
            # save it into a temp file and pass it to the prog-analysis tool
            package_prefix_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
            for prefix in package_prefix:
                package_prefix_file.write(prefix + "\n")
            package_prefix_file.close()

        try:
            if CG_GENERATOR == CG_GENERATOR_SOOT:
                # cd prog-analysis/ ; mvn clean package ; cd ..
                # java -jar prog-analysis/target/prog-analysis-1.0.jar --task gen-cg --jar-path jar_file --out cg_file
                cmd = f"java -jar prog-analysis/target/prog-analysis-1.0.jar --task gen-cg --cg-type spark --jar-path {jar_file} --out {cg_file}"
                if package_prefix:
                    cmd += f" --package-prefix {package_prefix_file.name}"
            elif CG_GENERATOR == CG_GENERATOR_TAIE:
                cmd = f"java -jar pa-taie/target/pa-taie-1.0.jar -o {cg_file}"
                if package_prefix:
                    cmd += f" -c {package_prefix_file.name}"
                target_jars = f" -j {jar_file}"
                if cve_id:
                    cve_annotation_file = f"{ANNOTATIONS_DIR}/{cve_id}/config.json"
                    if os.path.exists(cve_annotation_file):
                        print(f"[*] Loading cve annotations from <{cve_annotation_file}>")
                        cve_annotations = load_from_json(cve_annotation_file)
                        if "reflection_annotations" in cve_annotations:
                            cmd += f" -r {cve_annotations['reflection_annotations']}"
                        if "only-app-code" in cve_annotations:
                            if gav in cve_annotations["only-app-code"]:
                                if cve_annotations["only-app-code"][gav]:
                                    cmd += " --only-app"
                            else:
                                cmd += " --only-app"
                        if "supplementary_ga" in cve_annotations:
                            if gav in cve_annotations["supplementary_ga"]:
                                for supplementary_gav in cve_annotations["supplementary_ga"][gav]:
                                    supplementary_jar_file = download_gav_jar(supplementary_gav)
                                    if not supplementary_jar_file:
                                            print(f"[-] Failed to download supplementary GAV <{supplementary_gav}>")
                                            continue
                                    if supplementary_jar_file:
                                            print("[*] Adding supplementary GAV <{supplementary_gav}> for callgraph generation")
                                            target_jars += f" {supplementary_jar_file}"
                                            supplementary_package_prefix = get_gav_package_prefix_new(supplementary_gav, supplementary_jar_file)
                                            if supplementary_package_prefix:
                                                # append the package prefix to the temp file
                                                with open(package_prefix_file.name, "a") as f:
                                                    for prefix in supplementary_package_prefix:
                                                        f.write(prefix + "\n")
                cmd += target_jars
            else:
                print(f"[-] Unknown call graph generator: {CG_GENERATOR}")
                if package_prefix:
                    os.unlink(package_prefix_file.name)
                return None

            subprocess.run(cmd, shell=True, timeout=CALLGRAPH_TIMEOUT, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[-] Error: {e}")
            return None
        except subprocess.TimeoutExpired:
            print(f"[-] Timeout expired after {CALLGRAPH_TIMEOUT // 60} minutes while generating callgraph for <{gav}>")
            return None
        finally:
            if package_prefix_file:
                if os.path.exists(package_prefix_file.name):
                    os.unlink(package_prefix_file.name)
                        
        filter_cg(cg_file, package_prefix)

        return cg_file


def get_target_versions(ga, workdir):
    # check whether the `up` file exists (the root GA does not have an `up` file)
    ga_ups = get_upstream_ga_set(ga, workdir)
    if not ga_ups:
        return None

    target_versions = set()
    # for each ga_up in ga_ups, read the f"{cve_workdir}/{g}/{a}/filtered_gav_deps_cg.json" file
    # and get the versions of the ga_down
    for ga_up in ga_ups:
        g, a = ga_up.split(":")
        filtered_gav_deps_cg = load_from_json(f"{workdir}/{g}/{a}/filtered_gav_deps_cg.json")
        ga_down_data = filtered_gav_deps_cg["deps"][ga]
        for versions in ga_down_data.values():
            target_versions.update(versions)
    
    return list(target_versions)


entrypoints_cache = dict()


def get_entry_points(targets, cg_file):
    # check the cache
    cache_key = (tuple(targets), cg_file)
    if cache_key in entrypoints_cache:
        return entrypoints_cache[cache_key]

    # load cg_file json file (nodes, edges)
    # for each sink_func in sink_funcs, we need to find all the ancestors of the sink_func
    # whose "modifier" is "public" or "protected"
    data = load_from_json(cg_file)
    G = nx.DiGraph()
    for node in data.get('nodes', []):
        signature = node.get('signature')
        if signature:
            G.add_node(signature, modifier=node.get('modifier'))
    
    for edge in data.get('edges', []):
        src = edge.get('src')
        tgt = edge.get('tgt')
        if src and tgt:
            G.add_edge(src, tgt)
    
    # get the reverse graph
    G_reverse = G.reverse(copy=True)
    
    reachable_nodes = set()
    # BFS
    for t in targets:
        if t not in G_reverse:
            continue
        queue = deque([t])
        while queue:
            cur = queue.popleft()
            if cur in reachable_nodes:
                continue
            reachable_nodes.add(cur)
            for pred in G_reverse.neighbors(cur):
                if pred not in reachable_nodes:
                    queue.append(pred)
    
    public_protected_nodes = {node for node in reachable_nodes if G.nodes[node].get('modifier') in ['public', 'protected']}
    entrypoints_cache[cache_key] = public_protected_nodes
    return list(public_protected_nodes)


def get_down_callers(entrypoints, gav_down_cg_file):
    # load gav_down_cg_file json file
    # for each edge, check whether the tgt is in the entrypoints
    # if so, add the src to the callers of the tgt
    try:
        gav_down_cg = load_from_json(gav_down_cg_file)
    except:
        print(">>>>>>> ", gav_down_cg_file)
        raise
    callers = dict()
    for edge in gav_down_cg["edges"]:
        if edge['tgt'] in entrypoints:
            if edge['tgt'] not in callers:
                callers[edge['tgt']] = set()
            callers[edge['tgt']].add(edge['src'])
    # convert the set to list
    for ee, ers in callers.items():
        callers[ee] = list(ers)
    return callers


def get_sink_functions(ga, workdir):
    # check whether the `up` file exists (the root GA does not have an `up` file)
    ga_ups = get_upstream_ga_set(ga, workdir)
    if not ga_ups:
        return None

    sink_funcs = dict()
    # for each ga_up in ga_ups, read the f"{cve_workdir}/{g}/{a}/dep_calls.json" file
    for ga_up in ga_ups:
        g, a = ga_up.split(":")
        dep_calls = load_from_json(f"{workdir}/{g}/{a}/dep_calls.json")
        # parse the dep_calls file and get the sink functions
        ga_down_data = dep_calls["calls"][ga]
        for v_down_data in ga_down_data.values():
            for v_down, calls in v_down_data.items():
                sink_funcs[v_down] = list(set(func for sublist in calls.values() for func in sublist))

    return sink_funcs


def get_upstream_ga_set(ga, workdir):
    up_file_path = f"{workdir}/{ga.replace(':', '/')}/{UPSTREAM_GA_FILE}"
    if os.path.exists(up_file_path):
        with open(up_file_path, "r") as f:
            return set(f.read().strip().split("\n"))
    else:
        return set()


def add_upstream_ga(ga_down, workdir, ga_up):
    up_file_path = f"{workdir}/{ga_down.replace(':', '/')}/{UPSTREAM_GA_FILE}"
    lock_file = f"{up_file_path}.lock"
    lock = FileLock(lock_file)
    with lock.acquire(timeout=600):
        current_set = get_upstream_ga_set(ga_down, workdir)
        if not ga_up in current_set:
            with open(up_file_path, "a") as f:
                f.write(f"{ga_up}\n")


def clear_upstream_ga(ga_down, workdir):
    up_file_path = f"{workdir}/{ga_down.replace(':', '/')}/{UPSTREAM_GA_FILE}"
    lock_file = f"{up_file_path}.lock"
    lock = FileLock(lock_file)
    with lock.acquire(timeout=600):
        # clear the file
        with open(up_file_path, "w") as f:
            f.write("")


def load_old_target_functions(ga, workdir):
    target_func_file = f"{workdir}/{ga.replace(':', '/')}/tfs.json"
    if os.path.exists(target_func_file):
        return load_from_json(target_func_file)

    return None


def save_new_target_functions(ga, workdir, target_func):
    target_func_file = f"{workdir}/{ga.replace(':', '/')}/tfs.json"
    save_to_json(target_func, target_func_file)


def check_merge_diff_vfs(old_sink_funcs, sink_funcs):
    if not old_sink_funcs:
        return True, sink_funcs, sink_funcs
    if not sink_funcs:
        return False, old_sink_funcs, dict()

    has_new_tfs = False
    merged_funcs = {}
    added_funcs = {}

    all_keys = set(old_sink_funcs.keys()).union(sink_funcs.keys())

    for key in all_keys:
        old_list = set(old_sink_funcs.get(key, []))
        new_list = set(sink_funcs.get(key, []))

        if not new_list.issubset(old_list):
            has_new_tfs = True

        merged_list = old_list.union(new_list)
        merged_funcs[key] = list(merged_list)

        added_list = new_list - old_list
        if added_list:
            added_funcs[key] = list(added_list)

    return has_new_tfs, merged_funcs, added_funcs


def init_dep_dirs(ga_up, gav_deps, workdir):
    for ga_down in gav_deps:
        ensure_dir(f"{workdir}/{ga_down.replace(':', '/')}")
        add_upstream_ga(ga_down, workdir, ga_up)


def parse_signature(signature):
    if not (signature.startswith('<') and signature.endswith('>')):
        return None
    try:
        inner = signature[1:-1]
        class_and_rest = inner.split(': ', 1)
        if len(class_and_rest) != 2:
            return None
        class_name, rest = class_and_rest
        return_type_and_method = rest.split(' ', 1)
        if len(return_type_and_method) != 2:
            return None
        _, method_and_params = return_type_and_method
        method_name = method_and_params.split('(', 1)[0]
        params = method_and_params.split('(', 1)[1].rstrip(')')
        return class_name, method_name, params
    except Exception:
        return None


def parse_vf(vf):
    try:
        class_and_rest = vf.split(':', 1)
        class_name = class_and_rest[0]
        method_and_params = class_and_rest[1]
        method_name = method_and_params.split('(', 1)[0]
        params = method_and_params.split('(', 1)[1].rstrip(')')
        return class_name, method_name, params
    except Exception:
        return None


def load_orig_gav(cve_id):
    orig_dataset = load_from_json(f"{ORIGINAL_DATASET_DIR}/cve.json")
    return orig_dataset[cve_id]["gav"]


def normalize_cve_info(cve_info, cve_id=None):
    try:
        vuln_functions = cve_info["vuln_functions"]
    except KeyError:
        print(f"[-] Fail to load CVE VFs or VVs")
        return True

    modified = False
    gav_from_original_dataset = None
    for vf in vuln_functions:
        if not vf.startswith('<'):
            if not gav_from_original_dataset:
                gav_from_original_dataset = load_orig_gav(cve_info["id"])
            modified = True
            gav = gav_from_original_dataset
            jar_file = download_gav_jar(gav)
            if jar_file == None or jar_file == False:
                print(f"[-] Failed to download <{gav}>")
                continue
            # get the package prefix
            package_prefix = get_gav_package_prefix_new(gav, jar_file)
            if not package_prefix:
                print(f"[-] Failed to find package prefix for <{gav}>")
                continue
            cg = gen_gav_cg(gav, package_prefix, cve_id)
            if not cg:
                print(f"[-] Failed to generate CG for <{gav}>")
                continue
            parsed_vf = parse_vf(vf)
            cg_info = load_from_json(cg)
            nodes = [node['signature'] for node in cg_info['nodes']]
            for node in nodes:
                parsed_node = parse_signature(node)
                if parsed_node:
                    class_name, method_name, params = parsed_node
                    if class_name == parsed_vf[0] and method_name == parsed_vf[1] and params == parsed_vf[2]:
                        # we found the function in the CG
                        print(f"[+] Normalized VF: {vf} -> {node}")
                        cve_info["vuln_functions"].remove(vf)
                        cve_info["vuln_functions"].append(node)
                        break
    
    if modified:
        # save the modified cve_info
        cve_path = f"{CVE_DATASET_DIR}/{cve_info['id']}.json"
        print(f"[+] Saving modified CVE info to <{cve_path}>")
        save_to_json(cve_info, cve_path)
    # return modified
    return modified


def init_db(db_path=GAV_PREFIX_DB):
    conn = sqlite3.connect(db_path, timeout=30)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS gav_package_prefix (
            group_id TEXT,
            artifact_id TEXT,
            version TEXT,
            package_prefixes TEXT,
            reflection INTEGER DEFAULT -1,
            PRIMARY KEY (group_id, artifact_id, version)
        )
    ''')
    conn.commit()
    conn.close()


def global_init():
    ensure_dir(WORKDIR)
    ensure_dir(CALLGRAPH_DIR)
    ensure_dir(JAR_DIR)
    ensure_dir(GLOBAL_DEPS_DIR)
    init_db()


def main():
    parser = argparse.ArgumentParser(description="CVE Analyzer")
    parser.add_argument("--cve", required=True, help="CVE ID to analyze")
    parser.add_argument("--proc-num-deps", type=int, default=3, help="Number of processes for dependency filtering")
    parser.add_argument("--proc-num-cg", type=int, default=5, help="Number of processes for call graph filtering")
    parser.add_argument("--cg-tool", type=str, default="soot", choices=["soot", "taie"], help="Tool for call graph generation")
    args = parser.parse_args()

    global CG_GENERATOR, CALLGRAPH_DIR
    if args.cg_tool == "soot":
        CG_GENERATOR = CG_GENERATOR_SOOT
        CALLGRAPH_DIR = CALLGRAPH_DIR_SOOT
    elif args.cg_tool == "taie":
        CG_GENERATOR = CG_GENERATOR_TAIE
        CALLGRAPH_DIR = CALLGRAPH_DIR_TAIE

    global_init()

    cve_id = args.cve.upper()

    print(f"+++++ {cve_id} +++++")

    cve_info = load_cve_info(args.cve)

    ## As the final CVE dataset has been generated, the normalization step is not needed anymore.
    # # if vuln_functions is not normalized, we need to normalize it, and then ask user to run again
    # if normalize_cve_info(cve_info):
    #     print(f"[*] Please run the script again with the normalized CVE info")
    #     sys.exit(0)

    ga = f"{cve_info['groupId']}:{cve_info['artifactId']}"
    vuln_versions = cve_info["vuln_versions"]
    vuln_functions = cve_info["vuln_functions"]

    cve_workdir = f"{WORKDIR}/{CG_GENERATOR}_analysis/{args.cve}"
    ensure_dir(cve_workdir)

    ROOT = True
    worklist = [ga]
    target_versions = list()
    while worklist:
        item = worklist.pop(0)
        print(f"+++++ CURRENT: <{item}> | REMAINDER: {len(worklist)} +++++")
        g, a = item.split(":")
        ga_ups = get_upstream_ga_set(item, cve_workdir)
        if not ga_ups:
            if not ROOT:
                continue

        if ROOT:
            print(f"[*] Analyzing <{item} (ROOT)>")
        else:
            print(f"[*] Analyzing <{item}> (active ga_ups: {ga_ups})")

        old_sink_funcs = load_old_target_functions(item, cve_workdir)
        if ROOT:
            sink_funcs = {tgt_ver: vuln_functions for tgt_ver in vuln_versions}
        else:
            sink_funcs = get_sink_functions(item, cve_workdir)

        has_new_tfs, new_sink_funcs, added_sink_funcs = check_merge_diff_vfs(old_sink_funcs, sink_funcs)
        if not has_new_tfs:
            print(f"[!] No new target functions found for <{item}>")
            continue

        # use added_sink_funcs for this iteration

        state_changed = False
        filtered_gav_deps_cg_path = f"{cve_workdir}/{g}/{a}/filtered_gav_deps_cg.json"
        final_result_exists = False
        if not os.path.exists(filtered_gav_deps_cg_path):
            print(f"[+] {filtered_gav_deps_cg_path} does not exist (state_changed -> true)")
            state_changed = True
        else:
            final_result_exists = True

        ensure_dir(f"{cve_workdir}/{g}/{a}")

        # step 1: find all dependencies for the GA
        # output: ga_deps.json
        gen_ga_deps(item, cve_workdir)

        # step 2: find all GAV dependencies for the GA and filter out some GA deps
        #         based on vulnerable version mapping
        # output: gav_deps.json
        target_versions = list(added_sink_funcs.keys())
        changed, gav_deps = gen_gav_deps(item, target_versions, cve_workdir)
        if not changed:
            print(f"[!] gav_deps.json not changed")

        # step 3: filter out GAVs that do not directly depend on the vulnerable GAVs
        # output: filtered_gav_deps.json
        changed, filtered_gav_deps = filter_gav_deps(item, gav_deps=gav_deps, workdir=cve_workdir, proc_num=args.proc_num_deps)
        if not changed:
            print(f"[!] filtered_gav_deps.json not changed")

        # step 4: filter out GAVs based on CG-level reachability
        # output: filtered_gav_deps_cg.json
        # <GAV-0 sinks> (VFs) -> <GAV-0 sources> (EntryPoints) -> <GAV-1 sinks> -> <GAV-1 sources> -> ...
        state_changed, filtered_gav_deps_cg = filter_gav_deps_cg(cve_id, item, added_sink_funcs, filtered_gav_deps=filtered_gav_deps, workdir=cve_workdir, proc_num=args.proc_num_cg)

        # only save the new target functions after the filtering process
        save_new_target_functions(item, cve_workdir, new_sink_funcs)
        if state_changed:
            # step 5: add the filtered GAVs to the worklist
            print(f"[+] <{item}> (state_changed: {state_changed}, ROOT: {ROOT})")
            init_dep_dirs(item, filtered_gav_deps_cg["deps"].keys(), cve_workdir)
            worklist.extend(filtered_gav_deps_cg["deps"].keys())
        else:
            print(f"[!] No new GAVs found for <{item}> (state_changed -> false)")

        if ROOT:
            ROOT = False


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Bye!")
        sys.exit(0)

