# VPC CLI Tool - Build Your Own Virtual Private Cloud

![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Networking](https://img.shields.io/badge/Networking-Native-green)

A complete Virtual Private Cloud (VPC) implementation using Linux networking primitives. This project recreates AWS VPC functionality from scratch using network namespaces, bridges, veth pairs, and iptables.

**By Kefas Lungu (TechMarshal)** - HNG13 DevOps Stage 4

---

## 🎯 Features

- ✅ Create isolated VPCs with custom CIDR ranges
- ✅ Add public and private subnets
- ✅ Automatic NAT gateway for public subnets
- ✅ Intra-VPC routing between subnets
- ✅ Inter-VPC isolation by default
- ✅ VPC peering with controlled connectivity
- ✅ Firewall rules (Security Groups) via JSON policies
- ✅ Deploy applications in subnets
- ✅ Comprehensive connectivity testing
- ✅ Clean resource management

---

## 🏗️ Architecture

```
VPC (10.0.0.0/16)
│
├── Bridge (br-vpc1) [10.0.0.1]
│   │
│   ├── Public Subnet (10.0.1.0/24)
│   │   ├── Namespace: ns-public
│   │   ├── veth pair: veth-public-br ↔ veth-public
│   │   ├── NAT: Enabled (Internet access)
│   │   └── Apps: HTTP server on port 8080
│   │
│   └── Private Subnet (10.0.2.0/24)
│       ├── Namespace: ns-private
│       ├── veth pair: veth-private-br ↔ veth-private
│       ├── NAT: Disabled (No internet)
│       └── Apps: HTTP server on port 8081
│
└── Peering → VPC2 (via veth pair between bridges)
```

---

## 📋 Prerequisites

- Linux system (Ubuntu 20.04+ recommended)
- Root access (`sudo`)
- Python 3.6+
- Standard Linux networking tools:
  - `ip` (iproute2)
  - `iptables`
  - `bridge-utils` (optional, for inspection)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vpc-cli-tool.git
cd vpc-cli-tool

# Make the script executable
chmod +x vpcctl

# Verify prerequisites
ip --version
iptables --version
python3 --version
```

---

## 🚀 Quick Start

### 1. Create a VPC

```bash
sudo ./vpcctl create-vpc myvpc 10.0.0.0/16
```

### 2. Add Subnets

```bash
# Public subnet (with NAT)
sudo ./vpcctl add-subnet myvpc public 10.0.1.2/24 --type public

# Private subnet (no internet)
sudo ./vpcctl add-subnet myvpc private 10.0.2.2/24 --type private
```

### 3. Deploy Applications

```bash
# Deploy HTTP server in public subnet
sudo ./vpcctl deploy-app public --port 8080

# Deploy HTTP server in private subnet
sudo ./vpcctl deploy-app private --port 8081
```

### 4. Test Connectivity

```bash
# Run automated tests
sudo ./vpcctl test

# Manual tests
ip netns exec ns-public ping -c 3 10.0.2.2    # Should work (intra-VPC)
ip netns exec ns-public ping -c 3 8.8.8.8     # Should work (public has NAT)
ip netns exec ns-private ping -c 3 8.8.8.8    # Should fail (private blocked)
```

### 5. Clean Up

```bash
sudo ./vpcctl delete-vpc myvpc
```

---

## 📚 Complete Command Reference

### VPC Management

| Command | Description | Example |
|---------|-------------|---------|
| `create-vpc` | Create a new VPC | `sudo ./vpcctl create-vpc vpc1 10.0.0.0/16` |
| `delete-vpc` | Delete a VPC
