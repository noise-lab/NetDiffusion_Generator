# NetDiffusion: High-Fidelity Synthetic Network Traffic Generation

<img src="https://github.com/noise-lab/NetDiffusion_Code/assets/47127634/a24e88af-99cb-4a69-9130-d9e84e5a0fbd" width="300"/>

## Introduction

NetDiffusion is an innovative tool designed to address the challenges of obtaining high-quality, labeled network traces for machine learning tasks in networking. Privacy concerns, data staleness, and the limited availability of comprehensive datasets have long hindered research and development efforts. NetDiffusion leverages a controlled variant of a Stable Diffusion model to generate synthetic network traffic that not only boasts high fidelity but also adheres to protocol specifications.

Our approach outperforms current state-of-the-art synthetic trace generation methods by producing packet captures that exhibit higher statistical similarity to real network traffic. This improvement is crucial for enhancing machine learning model training and performance, as well as for supporting a wide range of network analysis and testing tasks beyond ML-centric applications.

## Features

- **High-Fidelity Synthetic Data:** Generate network traffic that closely resembles real-world data in terms of statistical properties and protocol compliance.
- **Compatibility:** Produced traces are compatible with common network analysis tools, facilitating easy integration into existing workflows.
- **Versatility:** Supports a wide array of network tasks, extending the utility of synthetic traces beyond machine learning applications.
- **Open Source:** NetDiffusion is open-source, encouraging contributions and modifications from the community to meet diverse needs.

## Installation (Current support for Linux only)

```bash
# SSH to Linux server via designated port (see following for example)
ssh -L 7860:LocalHost:7860 username@server_address

# Clone the repository
git clone git@github.com:noise-lab/NetDiffusion_Generator.git

# Navigate to the project directory
cd NetDiffusion_Generator

# Install dependencies in the virtual env of choice (we recommend Conda)
pip install -r requirements.txt
```

## Import Data
Store raw pcaps used for fine-tuning into 'NetDiffusion_Code/data/fine_tune_pcaps' with the application/service labels as the filenames, e.g.,'netflix_01.pcap'.

## Data Preprocessing and Fine-Tune Task Creation
```bash
# Navigate to preprocessing dir
cd data_preprocessing/

# Run preprocessing conversions
python3 pcap_to_img.py

# Navigate to fine-tune dir and the khoya subdir for task creation (replace the number in 20_network with the average number of pcaps per traffic type used for fine-tuning)
cd ../fine_tune/kohya_ss_fork/model_training/
mkdir -p example_task/{image/20_network,log,model}

# leverage Stable Diffusion WebUI for initial caption creation
cd ../../sd-webui-fork/stable-diffusion-webui/
cd
# Lunch WebUI
bash webui.sh
```
1. Open the WebUI via the ssh port on the preferred browser, example address: http://localhost:7860/
2. Under extras/batch_from_directory, enter the absolute path for `/NetDiffusion_Code/data/preprocessed_fine_tune_imgs` and `/NetDiffusion_Code/fine_tune/kohya_ss_fork/model_training/test_task/image/1_network` as the input/output directories.