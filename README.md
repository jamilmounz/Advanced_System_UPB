# Advanced Networked Systems SS24 Labs

This repository contains code skeleton for the labs of Advanced Networked Systems SS24 at Paderborn University, Germany. There are in total 5 labs, which will be released one by one throughout the semester.

## Lab 1: Hey Swiches and Routers
## Overview

In this lab, we implement a custom SDN controller using **Ryu** and build a virtual network using **Mininet**. The goal is to simulate:

- L2 Ethernet switches (learning switches)
- An L3 router (with ARP, TTL, and forwarding logic)
- Security policies (firewall rules)
- A realistic network topology with internal and external hosts

## Network Topology

- 3 OpenFlow switches(s1,s2,s3)
- 4 hosts with specific IP configuration
- The topology resembles
  - Internal hosts subnet (10.0.1.0/24)
  - Server subnet (10.0.2.0/24)
  - External connection (192.168.1.0/24)
  - Switch s3 functioning as a router

## Requirements
- Python 3
- Mininet
- Open vSwitch
- Ryu

## Repository Structure
- `run_network.py` - Mininet topology implementation
- `ans_controller.py` - Ryu controller implementation

## Usage
```bash
# Exit Mininet if running
exit

# Clean Mininet resources
sudo mn -c

# Start the Ryu controller
ryu-manager ans_controller.py

# In another terminal, start the network simulation
sudo python3 run_network.py
