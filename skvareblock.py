#!/usr/bin/env python3

import argparse
import shutil
import subprocess
import sys
import urllib.request

# Default name for block
firewall_ipset = "blockipset"

never_block = ['127.0.0.0', '127.0.0.1', '0.0.0.0']

# Ip lists to block
droplist_urls = [
    'https://www.spamhaus.org/drop/drop.txt',
    'https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt',
    'http://www.ipdeny.com/ipblocks/data/countries/cn.zone'
]


def sanitize_droplist(ips: list, comment_characters: list) -> list:
    """
    Check if a comment character exist in an IP line and
    remove everything the comment.
    Return the list of sanitized IP addresses in a list with blank lines removed
    """
    sanitized_ips = []

    for ip in ips:
        ip_line = next((ip.split(c)[0] for c in comment_characters if c in ip), ip)
        stripped_line = ip_line.strip()
        if stripped_line and not any(nb in ip_line for nb in never_block):
            sanitized_ips.append(stripped_line)

    return sanitized_ips


def fetch_droplist(url: str) -> list:

    response = urllib.request.urlopen(url)
    data = response.read()
    return data.decode('utf-8').split('\n')


class Ipset:

    def __init__(self, name: str, method: str, data_type: str, extra_args: list=None):
        if not shutil.which("ipset"):
            raise FileNotFoundError

        self.name = name
        self.method = method
        self.data_type = data_type
        self.extra_args = extra_args

    def create(self):
        arguments = ['ipset', 'create', self.name, f"{self.method}:{self.data_type}"]

        if self.extra_args:
            arguments.extend(self.extra_args)

        try:
            ipset = subprocess.run(arguments, check=True)
        except subprocess.CalledProcessError:
            raise

        return ipset

    def add_ips(self, ips: list):
        arguments = ['ipset', 'add', self.name]

        for ip in ips:
            try:
                subprocess.run(arguments + [ip], check=True)
            except subprocess.CalledProcessError:
                raise

    def swap(self, swap_ipset: str):
        """
        swap the ipset
        """
        arguments = ['ipset', 'swap', self.name, swap_ipset]

        try:
            subprocess.run(arguments, check=True)
        except subprocess.CalledProcessError:
            raise

    def destroy(self):
        """
        Destroy the ipset
        """
        arguments = ['ipset', 'destroy', self.name]

        try:
            subprocess.run(arguments, check=True)
        except subprocess.CalledProcessError:
            raise


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('ipset', nargs='?', default=firewall_ipset)
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    return args


def print_verbose(message: str, verbose: bool):
    if verbose:
        print(message)


def main():
    args = parse_arguments()

    ipset_name = args.ipset
    verbose = args.verbose

    print_verbose(f"Creating ipset: {args.ipset}", verbose)

    try:
        temp_ipset = Ipset(f"temp_{ipset_name}", "hash", "net", extra_args=['-exist'])
    except FileNotFoundError:
        sys.exit("ipset command not found")

    try:
        temp_ipset_return = temp_ipset.create()
    except subprocess.CalledProcessError as e:
        sys.exit(f"Failed to create ipset: {e.args}\n{e.stderr}")

    ip_list = []
    for u in droplist_urls:
        for ipl in sanitize_droplist(fetch_droplist(u), [';', '#']):
            if ipl not in ip_list:
                ip_list.append(ipl)

    try:
        temp_ipset.add_ips(ip_list)
    except subprocess.CalledProcessError as e:
        sys.exit(f"Failed to add ips to ipset: {e.args}\n{e.stderr}")

    # Create main ipset if doesn't exist
    try:
        ipset = Ipset(ipset_name, "hash", "net", extra_args=['-exist'])
    except FileNotFoundError:
        sys.exit("ipset command not found")

    try:
        ipset_return = ipset.create()
    except subprocess.CalledProcessError as e:
        sys.exit(f"Failed to create ipset: {e.args}\n{e.stderr}")

    try:
        temp_ipset.swap(ipset.name)
    except subprocess.CalledProcessError as e:
        sys.exit(f"Failed to swap ipset: {e.args}\n{e.stderr}")

    # Destroy the temp
    try:
        temp_ipset.destroy()
    except subprocess.CalledProcessError as e:
        sys.exit(f"Failed to destroy ipset: {e.args}\n{e.stderr}")

    print_verbose(f"Created ipset {ipset_name} successfully", verbose)


if __name__ == "__main__":
    # execute only if run as a script
    main()
