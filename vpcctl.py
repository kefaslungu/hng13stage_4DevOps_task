#!/usr/bin/env python3
# HNG13 DevOps stage 4 task.
# By Kefas Lungu (TechMarshal)
import argparse
import subprocess
import json
import sys
import os
import logging
from datetime import datetime

# ---------- Logging Setup ----------
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(LOG_DIR, f"vpcctl_{timestamp}.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Just for cruz!
print("HNG13 DevOps stage 4 solution. By Kefas Lungu (TechMarshal)")

STATE_FILE = "vpc_state.json"

# Initialize state if it doesn't exist
if not os.path.exists(STATE_FILE):
    with open(STATE_FILE, "w") as f:
        json.dump({"vpcs": {}}, f, indent=4)

def _load_state():
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def _save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)
 
# ---------- Utility functions ----------

def run(cmd: list[str]):
    """Run a system command and print it nicely, handling errors gracefully."""
    logging.info(f"[+] {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        logging.warning(f"[!] Command failed: {' '.join(cmd)}")
        print(f"    Exit code: {e.returncode}")
        if e.stdout:
            logging.info(f"    Output: {e.stdout.strip()}")
        if e.stderr:
            logging.warning(f"    Error output: {e.stderr.strip()}")
    except FileNotFoundError:
        logging.error(f"[!] Command not found: {cmd[0]}")
    except PermissionError:
        logging.error(f"[!] Permission denied: {' '.join(cmd)} (run as root?)")
    except Exception as e:
        logging.error(f"[!] Unexpected error running command: {' '.join(cmd)}")
        logging.info(f"    {type(e).__name__}: {e}")

def exists_namespace(name: str) -> bool:
    """Check if a network namespace already exists."""
    result = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    return name in result.stdout

def exists_bridge(name: str) -> bool:
    """Check if a Linux bridge already exists."""
    result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    return name in result.stdout

# ---------- Core VPC Operations ----------

def create_vpc(vpc_name: str, cidr_block: str):
    state = _load_state()
    if vpc_name in state["vpcs"]:
        logging.warning(f"VPC {vpc_name} already exists in state.")
        return

    bridge = f"br-{vpc_name}"
    logging.info(f"Creating VPC '{vpc_name}' with CIDR {cidr_block}")

    if exists_bridge(bridge):
        logging.warning(f"Bridge {bridge} already exists in system, adding to state.")
    else:
        run(["ip", "link", "add", bridge, "type", "bridge"])
        run(["ip", "addr", "add", f"{cidr_block.split('/')[0]}/16", "dev", bridge])
        run(["ip", "link", "set", bridge, "up"])

    # Update state
    state["vpcs"][vpc_name] = {"cidr": cidr_block, "subnets": {}}
    _save_state(state)
    logging.info(f"VPC {vpc_name} created and state updated.")

def add_subnet(vpc_name: str, subnet_name: str, subnet_cidr: str):
    state = _load_state()
    if vpc_name not in state["vpcs"]:
        logging.error(f"VPC {vpc_name} not found in state. Create it first.")
        return
    if subnet_name in state["vpcs"][vpc_name]["subnets"]:
        logging.warning(f"Subnet {subnet_name} already exists in VPC {vpc_name} state.")
        return

    ns = f"ns-{subnet_name}"
    bridge = f"br-{vpc_name}"

    logging.info(f"Adding subnet {subnet_name} ({subnet_cidr}) to VPC {vpc_name}")

    if exists_namespace(ns):
        logging.warning(f"Namespace {ns} already exists in system, adding to state.")
    else:
        # Create namespace and veth pair
        run(["ip", "netns", "add", ns])
        veth_host = f"veth-{subnet_name}-br"
        veth_ns = f"veth-{subnet_name}"
        run(["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_ns])
        run(["ip", "link", "set", veth_ns, "netns", ns])
        run(["ip", "link", "set", veth_host, "master", bridge])
        run(["ip", "link", "set", veth_host, "up"])
        run(["ip", "netns", "exec", ns, "ip", "addr", "add", subnet_cidr, "dev", veth_ns])
        run(["ip", "netns", "exec", ns, "ip", "link", "set", veth_ns, "up"])
        run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])

    # Update state
    state["vpcs"][vpc_name]["subnets"][subnet_name] = subnet_cidr
    _save_state(state)
    logging.info(f"Subnet {subnet_name} added to VPC {vpc_name} state.")

def delete_vpc(vpc_name: str):
    state = _load_state()
    if vpc_name not in state["vpcs"]:
        logging.warning(f"VPC {vpc_name} not found in state.")
    else:
        bridge = f"br-{vpc_name}"
        logging.info(f"Deleting VPC {vpc_name}")

        # Delete namespaces
        result = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
        for line in result.stdout.strip().splitlines():
            ns = line.split()[0]
            if vpc_name in ns:
                logging.info(f"Deleting namespace {ns}")
                run(["ip", "netns", "del", ns])

        # Delete bridge
        if exists_bridge(bridge):
            run(["ip", "link", "set", bridge, "down"])
            run(["ip", "link", "del", bridge])
            logging.info(f"Bridge {bridge} deleted")
        else:
            logging.warning(f"Bridge {bridge} not found")

        # Remove from state
        del state["vpcs"][vpc_name]
        _save_state(state)
        logging.info(f"VPC {vpc_name} removed from state")
def test_vpc():
    state = _load_state()
    if not state["vpcs"]:
        logging.warning("No VPCs found to test.")
        return

    logging.info("Starting VPC tests...")

    for vpc_name, vpc_data in state["vpcs"].items():
        logging.info(f"Testing VPC: {vpc_name}")
        subnets = vpc_data.get("subnets", {})

        # 1. Test intra-VPC connectivity
        for src_name, src_cidr in subnets.items():
            src_ns = f"ns-{src_name}"
            for dest_name, dest_cidr in subnets.items():
                if src_name == dest_name:
                    continue
                dest_ip = dest_cidr.split("/")[0]
                logging.info(f"Pinging {dest_ip} from {src_ns}")
                try:
                    subprocess.run(
                        ["ip", "netns", "exec", src_ns, "ping", "-c", "2", dest_ip],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    logging.info(f"[✓] {src_ns} can reach {dest_ip}")
                except subprocess.CalledProcessError:
                    logging.warning(f"[x] {src_ns} cannot reach {dest_ip}")

def test_vpc():
    state = _load_state()
    if not state["vpcs"]:
        logging.warning("No VPCs found to test.")
        return

    logging.info("Starting VPC tests...")

    for vpc_name, vpc_data in state["vpcs"].items():
        logging.info(f"Testing VPC: {vpc_name}")
        subnets = vpc_data.get("subnets", {})

        # 1. Test intra-VPC connectivity
        for src_name, src_cidr in subnets.items():
            src_ns = f"ns-{src_name}"
            for dest_name, dest_cidr in subnets.items():
                if src_name == dest_name:
                    continue
                dest_ip = dest_cidr.split("/")[0]
                logging.info(f"Pinging {dest_ip} from {src_ns}")
                try:
                    subprocess.run(
                        ["ip", "netns", "exec", src_ns, "ping", "-c", "2", dest_ip],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    logging.info(f"[✓] {src_ns} can reach {dest_ip}")
                except subprocess.CalledProcessError:
                    logging.warning(f"[x] {src_ns} cannot reach {dest_ip}")

        # 2. Test NAT for public subnets
        for subnet_name, subnet_cidr in subnets.items():
            if "public" in subnet_name.lower():
                ns = f"ns-{subnet_name}"
                logging.info(f"Testing internet access from public subnet {ns}")
                try:
                    subprocess.run(
                        ["ip", "netns", "exec", ns, "ping", "-c", "2", "8.8.8.8"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    logging.info(f"[✓] {ns} can reach the internet")
                except subprocess.CalledProcessError:
                    logging.warning(f"[x] {ns} cannot reach the internet")

        # 3. Test that private subnets do NOT have internet
        for subnet_name, subnet_cidr in subnets.items():
            if "private" in subnet_name.lower():
                ns = f"ns-{subnet_name}"
                logging.info(f"Testing internet access from private subnet {ns}")
                try:
                    subprocess.run(
                        ["ip", "netns", "exec", ns, "ping", "-c", "2", "8.8.8.8"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    logging.warning(f"[x] {ns} should NOT reach the internet but did")
                except subprocess.CalledProcessError:
                    logging.info(f"[✓] {ns} cannot reach the internet as expected")

    logging.info("VPC tests completed.") 

def enable_ip_forwarding():
    """Enable IP forwarding on the host."""
    print("[*] Enabling IP forwarding...")
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1\n")
    print("[✓] IP forwarding enabled")

def enable_nat(vpc_name: str, public_subnet: str, iface: str = "eth0"):
    """Enable NAT for a VPC so its subnets can reach the internet."""
    bridge = f"br-{vpc_name}"
    print(f"\n[*] Enabling NAT for VPC {vpc_name} via {iface}")

    enable_ip_forwarding()

    # Apply masquerade for outgoing packets
    run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", public_subnet, "-o", iface, "-j", "MASQUERADE"])

    print(f"[✓] NAT enabled for {public_subnet} on {iface}")

def disable_nat(public_subnet: str, iface: str = "eth0"):
    """Disable NAT rules."""
    print(f"\n[*] Disabling NAT for {public_subnet}")
    run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", public_subnet, "-o", iface, "-j", "MASQUERADE"])
    print("[✓] NAT rule removed")

def enable_intra_vpc_routing(vpc_name: str, subnets: list):
    """Add routes in each subnet to reach other subnets in the same VPC."""
    print(f"[*] Enabling intra-VPC routing for {vpc_name}")
    bridge_ip = f"{vpc_name}.bridge"  # Optional, could be the bridge address
    for ns in subnets:
        ns_name = f"ns-{ns}"
        for dest in subnets:
            if dest == ns:
                continue
            # Add route to other subnet via bridge
            dest_subnet_cidr = subnets[dest]  # e.g., {"public": "10.0.1.0/24"}
            run([
                "ip", "netns", "exec", ns_name,
                "ip", "route", "add", dest_subnet_cidr, "dev", f"veth-{ns}"
            ])
    print("[✓] Intra-VPC routing enabled")

def peer_vpcs(vpc1: str, vpc2: str):
    """Peer two VPCs for controlled communication."""
    br1 = f"br-{vpc1}"
    br2 = f"br-{vpc2}"
    veth1 = f"veth-{vpc1}-to-{vpc2}"
    veth2 = f"veth-{vpc2}-to-{vpc1}"

    print(f"[*] Creating peering between {vpc1} and {vpc2}")

    # Create veth pair
    run(["ip", "link", "add", veth1, "type", "veth", "peer", "name", veth2])

    # Attach to bridges
    run(["ip", "link", "set", veth1, "master", br1])
    run(["ip", "link", "set", veth2, "master", br2])
    run(["ip", "link", "set", veth1, "up"])
    run(["ip", "link", "set", veth2, "up"])

    print(f"[✓] Peering established between {vpc1} and {vpc2}")

def load_policy(file_path: str):
    with open(file_path) as f:
        return json.load(f)

def apply_firewall_policy(ns_name: str, policy: dict):
    """Apply ingress rules inside a namespace."""
    for rule in policy.get("ingress", []):
        port = str(rule["port"])
        proto = rule.get("protocol", "tcp")
        action = rule["action"].upper()

        if action == "ALLOW":
            target = "ACCEPT"
        elif action == "DENY":
            target = "DROP"
        else:
            continue

        run([
            "ip", "netns", "exec", ns_name,
            "iptables", "-A", "INPUT", "-p", proto, "--dport", port, "-j", target
        ])
    print(f"[✓] Firewall rules applied to {ns_name}")

# List All VPCs
def list_vpcs():
    """List all VPC bridges (VPCs) and their status."""
    print("[*] Existing VPCs:")
    bridges = [line.split(":")[1].strip() for line in subprocess.run(
        ["ip", "link", "show"], capture_output=True, text=True
    ).stdout.splitlines() if "br-" in line]
    if not bridges:
        print("  None found.")
    else:
        for br in bridges:
            print(f"  - {br}")

# Show Subnets of a VPC
def show_subnets(vpc_name: str):
    """List all namespaces (subnets) connected to a VPC."""
    print(f"[*] Subnets in VPC '{vpc_name}':")
    result = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    subnets = [ns for ns in result.stdout.strip().splitlines() if vpc_name in ns]
    if not subnets:
        print("  None found.")
    else:
        for ns in subnets:
            ip_addr = subprocess.run(
                ["ip", "netns", "exec", ns, "ip", "addr", "show"],
                capture_output=True, text=True
            ).stdout
            print(f"  - {ns}\n{ip_addr}")

# ---------- CLI Parser ----------

def main():
    parser = argparse.ArgumentParser(description="Mini VPC CLI on Linux by Kefas Lungu (techmarshal)")
    subparsers = parser.add_subparsers(dest="command")

    # create-vpc
    c_vpc = subparsers.add_parser("create-vpc", help="Create a new VPC")
    c_vpc.add_argument("name", help="Name of the VPC")
    c_vpc.add_argument("cidr", help="CIDR range for the VPC (e.g., 10.0.0.0/16)")

    # add-subnet
    c_subnet = subparsers.add_parser("add-subnet", help="Add a subnet to a VPC")
    c_subnet.add_argument("vpc_name", help="Parent VPC name")
    c_subnet.add_argument("subnet_name", help="Subnet name")
    c_subnet.add_argument("cidr", help="Subnet CIDR (e.g., 10.0.1.2/24)")

    # delete-vpc
    d_vpc = subparsers.add_parser("delete-vpc", help="Delete a VPC and its subnets")
    d_vpc.add_argument("name", help="Name of the VPC")

    # enable-nat
    c_nat = subparsers.add_parser("enable-nat", help="Enable NAT for VPC")
    c_nat.add_argument("vpc_name", help="VPC name")
    c_nat.add_argument("subnet_cidr", help="Public subnet CIDR (e.g., 10.0.1.0/24)")
    c_nat.add_argument("--iface", default="eth0", help="Internet-facing interface (default: eth0)")

    # disable-nat
    d_nat = subparsers.add_parser("disable-nat", help="Disable NAT for subnet")
    d_nat.add_argument("subnet_cidr", help="Public subnet CIDR")
    d_nat.add_argument("--iface", default="eth0", help="Internet-facing interface (default: eth0)")

    # peer-vpcs
    p_parser = subparsers.add_parser("peer-vpcs", help="Peer two VPCs")
    p_parser.add_argument("vpc1", help="First VPC")
    p_parser.add_argument("vpc2", help="Second VPC")

    # enable-intra-routing
    r_parser = subparsers.add_parser("enable-routing", help="Enable intra-VPC routing")
    r_parser.add_argument("vpc_name", help="VPC name")
    r_parser.add_argument("subnets_json", help="JSON file with subnet names and CIDRs")
    fw_parser = subparsers.add_parser("apply-fw", help="Apply firewall policy from JSON")
    fw_parser.add_argument("subnet_name", help="Subnet name")
    fw_parser.add_argument("policy_file", help="JSON policy file")

    c_list = subparsers.add_parser("show-vpcs", help="List all existing VPCs")
    s_list = subparsers.add_parser("show-subnets", help="List all subnets in a VPC")
    s_list.add_argument("vpc_name", help="VPC name")

    args = parser.parse_args()

    # ---------- Command Map ----------
    COMMANDS = {
        "create-vpc": lambda args: create_vpc(args.name, args.cidr),
        "add-subnet": lambda args: add_subnet(args.vpc_name, args.subnet_name, args.cidr),
        "delete-vpc": lambda args: delete_vpc(args.name),
        "enable-nat": lambda args: enable_nat(args.vpc_name, args.subnet_cidr, args.iface),
        "disable-nat": lambda args: disable_nat(args.subnet_cidr, args.iface),
        "peer-vpcs": lambda args: peer_vpcs(args.vpc1, args.vpc2),
        "show-vpcs": lambda args: list_vpcs(),
        "show-subnets": lambda args: show_subnets(args.vpc_name),
        "enable-routing": lambda args: enable_intra_vpc_routing(
            args.vpc_name, json.load(open(args.subnets_json, "r"))
        ),
                "apply-fw": lambda args: apply_firewall_policy(
            f"ns-{args.subnet_name}", load_policy(args.policy_file)
        ),
        "test-vpc": lambda args: test_vpc()
    }

    # ---------- Dispatch command ----------
    if args.command in COMMANDS:
        COMMANDS[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[x] You must run this script as root (sudo).")
        sys.exit(1)
    main()
