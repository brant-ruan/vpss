<p align="center">
  <img src="images/vpss_logo.jpg" alt="vpss-logo" height="251" />
</p>

## Introduction (Under Construction)

Stay tuned :P

## Installation

Please prepare a clean workspace and execute the following commands:

```bash
# within the workspace
git clone https://github.com/brant-ruan/vpss.git
mkdir workdir
```

Then, install the required Python packages:

```bash
# within the workspace
cd vpss
# It is recommended to create a virtual environment first
virtualenv -p /usr/bin/python3 venv
source venv/bin/activate
pip install -r requirements.txt
```

## Workflow

The workflow of VPSS is shown as below:

<img src="images/overview.jpg" alt="workflow" width="70%" />

You can refer to [the paper](https://arxiv.org/pdf/2506.01342) for more details.

### Step 1: Dependency Graph Construction

For the first time, you need to download the latest [Maven Central Repository (MCR) index](https://repo1.maven.org/maven2/.index/) data:

```bash
# within the workspace
mkdir -p workdir/mcr && cd workdir/mcr
wget https://repo1.maven.org/maven2/.index/nexus-maven-repository-index.gz
java -jar indexer-cli-5.1.1.jar --unpack nexus-maven-repository-index.gz --destination central-lucene-index --type full
```

After that, you will have a `central-lucene-index` folder under `workdir/mcr/`, which contains the MCR index data.



**Notes on Incremental Updates:** 

### Step 2: Vulnerable Function Identification


### Step 3: Vulnerability Propagation Analysis

To perform vulnerability propagation analysis, run the following command ()

```bash
python ./vpa-analyzer.py --cve CVE-2016-5393 --proc-num-deps 16 --proc-num-cg 16
```

Notes:

- We used Soot to perform static analysis and build the call graphs for experiments in this paper. Although we also tested with Tai-e, it is an experimental option and may require more effort to work properly.

### Step 4: VPSS Calculation


## Citation

If you use VPSS, please cite the [following paper](https://arxiv.org/pdf/2506.01342):

```
@inproceedings{ruan2025vpss,
  title={Propagation-Based Vulnerability Impact Assessment for Software Supply Chains},
  author={Ruan, Bonan and Lin, Zhiwei and Liu, Jiahao and Zhang, Chuqi and Ji, Kaihang and Liang, Zhenkai},
  booktitle={Proceedings of the 40th IEEE/ACM International Conference on Automated Software Engineering},
  year={2025}
}
```