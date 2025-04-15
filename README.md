<p align="center">
  <img width="500" alt="NetDiffusion Example Output" src="https://github.com/user-attachments/assets/0f52e0a8-2dc8-488e-a082-67fb9b2d4795">
</p>

# 🌐 NetDiffusion: High-Fidelity Synthetic Network Traffic Generation

<p align="center">
  <img width="800" alt="NetDiffusion Example Output" src="https://github.com/noise-lab/NetDiffusion_Generator/assets/47127634/804756f9-156e-4796-bea6-00d5d7bb1706">
</p>

---

## 📘 Introduction

**NetDiffusion** is an innovative tool designed to solve one of the core bottlenecks in networking ML research: the lack of high-quality, labeled, and privacy-preserving network traces.

Traditional datasets often suffer from:
- ⚠️ **Privacy concerns**
- 🕓 **Data staleness**
- 📉 **Limited diversity**

NetDiffusion addresses these issues by using a **protocol-aware Stable Diffusion model** to synthesize network traffic that is both **realistic** and **standards-compliant**.

> 🧪 The result? Synthetic packet captures that look and behave like real traffic—ideal for model training, testing, and simulation.

---

## ✨ Features

- ✅ **High-Fidelity Data Generation**  
  Generate synthetic traffic that matches real-world patterns and protocol semantics.

- 🔌 **Tool Compatibility**  
  Output traces are `.pcap` files—ready for use with Wireshark, Zeek, tshark, and other standard tools.

- 🛠️ **Multi-Use Support**  
  Beyond ML: Useful for system testing, anomaly detection, protocol emulation, and more.

- 💡 **Fully Open Source**  
  Built for the community. Modify, extend, and contribute freely.

---

## 📝 Note

- The original **NetDiffusion** was implemented using **Stable Diffusion 1.5**, which is now deprecated with outdated dependencies.
- This repo provides a **modern reimplementation using Stable Diffusion 3.0**, integrated with **InstantX/SD3-Controlnet-Canny**, preserving the framework’s core concepts while upgrading for compatibility and stability.

---

## 🗂 Project Structure

- 🔧 All core scripts for preprocessing, training, inference, and reconstruction are located in the [`scripts/`](./scripts/) directory.
- 📓 A step-by-step **Jupyter notebook** walks you through the entire pipeline:

  - 📦 **Dependency Installation**
  - 🧼 **Preprocessing (`.nprint` → `.png`)**
  - 🧠 **LoRA Fine-Tuning** on structured packet image embeddings
  - 🎨 **Diffusion-Based Generation** using ControlNet (Canny conditioning)
  - 🔄 **Post-Generation Processing**
    - Color correction
    - `.png` → `.nprint` → `.pcap` conversion
    - Replayable `.pcap` synthesis with protocol repair

> ⚙️ The reimplementation is fully modular and forward-compatible, enabling seamless experimentation with next-gen diffusion architectures.

---

## 📚 Citing NetDiffusion

If you use this tool or build on its techniques, please cite:

```bibtex
@article{jiang2024netdiffusion,
  title={NetDiffusion: Network Data Augmentation Through Protocol-Constrained Traffic Generation},
  author={Jiang, Xi and Liu, Shinan and Gember-Jacobson, Aaron and Bhagoji, Arjun Nitin and Schmitt, Paul and Bronzino, Francesco and Feamster, Nick},
  journal={Proceedings of the ACM on Measurement and Analysis of Computing Systems},
  volume={8},
  number={1},
  pages={1--32},
  year={2024},
  publisher={ACM New York, NY, USA}
}
