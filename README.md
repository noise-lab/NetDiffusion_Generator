# NetDiffusion: High-Fidelity Synthetic Network Traffic Generation

## Introduction

NetDiffusion is an innovative tool designed to address the challenges of obtaining high-quality, labeled network traces for machine learning tasks in networking. Privacy concerns, data staleness, and the limited availability of comprehensive datasets have long hindered research and development efforts. NetDiffusion leverages a controlled variant of a Stable Diffusion model to generate synthetic network traffic that not only boasts high fidelity but also adheres to protocol specifications.

Our approach outperforms current state-of-the-art synthetic trace generation methods by producing packet captures that exhibit higher statistical similarity to real network traffic. This improvement is crucial for enhancing machine learning model training and performance, as well as for supporting a wide range of network analysis and testing tasks beyond ML-centric applications.

## Features

- **High-Fidelity Synthetic Data:** Generate network traffic that closely resembles real-world data in terms of statistical properties and protocol compliance.
- **Compatibility:** Produced traces are compatible with common network analysis tools, facilitating easy integration into existing workflows.
- **Versatility:** Supports a wide array of network tasks, extending the utility of synthetic traces beyond machine learning applications.
- **Open Source:** NetDiffusion is open-source, encouraging contributions and modifications from the community to meet diverse needs.

## Installation

```bash
# Clone the repository
git clone git@github.com:noise-lab/NetDiffusion_Code.git

# Navigate to the project directory
cd NetDiffusion_Code

# Install dependencies in the virtual env of choice (we recommend Conda)
pip install -r requirements.txt
