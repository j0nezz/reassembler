# Reassembler - Towards a Global DDoS Attack Analysis Using Attack Fingerprints

This GitHub repository entails the source code and files developed as part of the Master's Thesis at the University of Zurich in 2022/2023.

## Project Structure
There are three main modules to this project

- **Reassembler:**
   The Reassembler module provides functionality to generate a global analysis from a set of attack fingerprints

- **Generator:**
   The Generator simulates a TCP SYN attack based on a simulated network. 
   The Fingerprints can be stored to a folder to create different scenarios.
   
   _Note: Instead of simulating fingerprints, the Reassembler can also be used with the [DDoS Dissector](https://github.com/j0nezz/ddos_dissector)._

- **Evaluation:**
  The evaluation module provides the functionality for running the experiments included in the thesis again.

## Installation and Setup

1. Clone the Reassembler repository
    ```bash
    git clone https://github.com/j0nezz/reassembler
    cd reassembler
    ```
2. Create a python virtual environment or conda environment for the reassembler and install the python requirements:

    Venv:
    ```bash
    python -m venv ./python-venv
    source python-venv/bin/activate
    pip install -r requirements.txt
    ```
    [Conda](https://docs.conda.io/projects/conda/en/latest/user-guide/tasks/manage-environments.html):
    ```bash
    conda create -n reassembler python=3.10
    conda activate reassembler
    conda install pip
    pip install -r requirements.txt
    ```
3. Run the reassembler
    ```bash
     python main.py
   ```
   
## Examples
### Simulating an Attack
```python
scenario = Generator([IPNetwork(f"{10 + i}.0.0.0/8") for i in range(5)], max_levels=3, max_clients=5, spoofed_pct=0.25)
fingerprints = (scenario
                .add_background_traffic(10)
                .set_random_attack_sources(5)
                .simulate_attack()
                .fingerprints)
```

The Generator provides a fluent API, making it easy to adapt certain parameters of the scenario on different runs
```python
for i in range(5):
    scenario.set_random_attack_sources(5 + i*5).simulate_attack().save_to_json(f"./example/{i}")
```

### Reassembler
The Reassembler can be used with different data sources and with simulated / real attack fingerprints.
The following examples show the available possibilities.

The `add_ground_truth_data` method can only be used in simulated scenarios and meant for evaluation, as it alters the output. 


**Simulated In-Memory Fingerprints**
```python
scenario = ...
Reassembler(fingerprint_data=scenario.fingerprints)
                 .reassemble()
                 .add_ground_truth_data(scenario.target, scenario.sources)
                 .save_to_json('./result')
```
**Simulated Fingerprints in Folder**
```python
Reassembler(fingerprint_folder='./example')
                 .reassemble()
                 .add_ground_truth_data(scenario.target, scenario.sources)
                 .save_to_json('./result')
```

**Real Fingerprints from Dissector**
```python
Reassembler(fingerprint_folder='./dissector-fp', simulated=False)
                 .reassemble()
                 .save_to_json('./result')
```

### Usage with the DDoS Dissector
To use the Reassembler with data from the DDoS Dissector, please use the [extended DDoS Dissector](https://github.com/j0nezz/ddos_dissector) which is a fork of the [original DDoS Dissector](https://github.com/ddos-clearing-house/ddos_dissector).
Make sure to use the reassembler with the `-e` flag, to produce fingerprints of the extended format.

**Example to run DDoS Dissector**

⚠️ _`main.py` referrs to the file of the DDoS Dissector, not the Reassembler_
```bash
python ./src/main.py -f ./target/traffic.pcap -e -l "192.168.50.4"  -n 5 --output ./dissector-fp
```
## Reassembler Output
The following example shows the resulting output of a custom scenario based on [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html) using the [DDoS Dissector](https://github.com/j0nezz/ddos_dissector).
```json
{
  "attack": {
    "start_time": "2018-11-03T15:28:00.776482+00:00",
    "end_time": "2018-11-03T21:35:47.776482+00:00",
    "duration_seconds": 22067.0
  },
  "target": {
    "ip": "192.168.50.4"
  },
  "intermediate_nodes": {
    "discarded_intermediate_nodes": 0,
    "nr_intermediate_nodes": 2,
    "detection_threshold": {
      "25": 0.5277473421668619,
      "50": 0.5503294973955934,
      "75": 0.572911652624325
    },
    "key_nodes": {
      "192.168.0.1": {
        "nr_packets": 2093500,
        "hops_to_target": 1.0,
        "detection_threshold": 0.5954938078530566,
        "time_start": "2018-11-03T15:28:00.776282+00:00",
        "time_end": "2018-11-03T21:35:47.776282+00:00",
        "fraction_of_total_attack": 1.0,
        "duration_seconds": 22067.0
      },
      "192.168.2.1": {
        "nr_packets": 1046531,
        "hops_to_target": 2.0,
        "detection_threshold": 0.5051651869381303,
        "time_start": "2018-11-03T15:28:09.666466+00:00",
        "time_end": "2018-11-03T21:35:31.666466+00:00",
        "fraction_of_total_attack": 0.4998953904943874,
        "duration_seconds": 22042.0
      }
    }
  },
  "sources": {
    "nr_sources": 25,
    "pct_spoofed": 0.4
  },
  "key": "30c8aa201ceff1847db9513a49a8d88f"
}
```

## Demo
### Generator
Simulating a network and generating fingerprints

https://github.com/j0nezz/reassembler/assets/12492528/8ceee8a4-2101-40e0-8168-6711883ac88e

### Reassembler
Global attack view based on fingerprints

https://github.com/j0nezz/reassembler/assets/12492528/be380d4e-c106-400b-ac3a-00d0e06af3b6




