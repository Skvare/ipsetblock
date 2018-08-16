#!/usr/bin/env python3

import argparse
import shutil
import subprocess
import sys
import urllib.request
import logging
from logging.handlers import RotatingFileHandler

"""
ipsetblock allows easy creation of ipsets from block lists
"""


class Ipset:

    def __init__(self, name: str, method: str, data_type: str, extra_args: list=None):
        if not shutil.which("ipset"):
            raise FileNotFoundError

        self.name = name
        self.method = method
        self.data_type = data_type
        self.extra_args = extra_args

    def create(self):
        arguments = ['ipset', 'create', self.name, "{}:{}".format(self.method, self.data_type)]

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


def print_verbose(message: str, verbose: bool):
    if verbose:
        print(message)


def get_logger(log_file: str, disable_logs: bool = False):

    log_formatter = logging.Formatter(
        '%(asctime)s %(levelname)s %(message)s')

    handler = RotatingFileHandler(
        log_file, mode='a', maxBytes=5 * 1024 * 1024, backupCount=2, encoding=None, delay=0)
    handler.setFormatter(log_formatter)
    handler.setLevel(logging.INFO)

    log = logging.getLogger('root')
    log.setLevel(logging.INFO)

    log.addHandler(handler)

    if disable_logs:
        log.disabled = True

    return log


def sanitize_droplist(ips: list,
                      comment_characters: list,
                      add_whitelist_ips=None) -> list:
    """
    Check if a comment character exist in an IP line and
    remove everything the comment.
    Return the list of sanitized IP addresses in a list with blank lines removed
    """
    sanitized_ips = []

    add_whitelist_ips = [] if add_whitelist_ips is None else add_whitelist_ips

    for ip in ips:
        ip_line = next((ip.split(c)[0] for c in comment_characters if c in ip), ip)
        stripped_line = ip_line.strip()
        if stripped_line and not any(nb in ip_line for nb in add_whitelist_ips):
            sanitized_ips.append(stripped_line)

    return sanitized_ips


def fetch_droplist(url: str) -> list:

    response = urllib.request.urlopen(url)
    data = response.read()
    return data.decode('utf-8').split('\n')


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('ipset', nargs='?', default="blockipset")
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-b', '--blacklisted_ips', default="blacklisted_ips")
    parser.add_argument('-w', '--whitelisted_ips', default="whitelisted_ips")
    parser.add_argument('-u', '--blacklist_urls', default="blacklist_urls")
    parser.add_argument('-l', '--logfile', default="ipsetblock.log")
    parser.add_argument('-m', '--method', default="hash", help="ipset method")
    parser.add_argument('-d', '--datatype', default="net", help="ipset datatype")
    args = parser.parse_args()

    return args


def get_lines(filename: str, comment: str = "#") -> list:
    try:
        with open(filename) as f:
            urls = f.readlines()
    except FileNotFoundError:
        raise

    # Remove whitespace and comments at the end of each line
    return [url.split(comment)[0].strip() if comment in url else url.strip()
            for url in urls if url]


def main():
    args = parse_arguments()

    ipset_name = args.ipset
    verbose = args.verbose
    blacklisted_ips_file = args.blacklisted_ips
    whitelisted_ips_file = args.whitelisted_ips
    blacklist_urls_file = args.blacklist_urls
    logfile = args.logfile

    ipset_method = args.method
    ipset_datatype = args.datatype

    logger = get_logger(logfile)

    print_verbose("Creating ipset: {}".format(ipset_name), verbose)

    try:
        droplist_urls = get_lines(blacklist_urls_file)
    except FileNotFoundError:
        sys.exit("No blacklist url file '{}' found".format(blacklist_urls_file))

    try:
        blacklist_ips = get_lines(blacklisted_ips_file)
    except FileNotFoundError:
        logger.info("No blacklist ip file '{}' found".format(blacklisted_ips_file))
        blacklist_ips = []
    else:
        logger.info("Added blacklisted ips from '{}'".format(blacklisted_ips_file))

    try:
        whitelist_ips = get_lines(whitelisted_ips_file)
    except FileNotFoundError:
        logger.info("No whitelist ip file '{}' found".format(whitelisted_ips_file))
        whitelist_ips = []
    else:
        logger.info("Added whitelisted ips from '{}'".format(whitelisted_ips_file))

    """
    Create a temporary ipset
    ipset create ${name} hash:net -exist
    """
    try:
        temp_ipset = Ipset(
            "temp_{}".format(ipset_name), ipset_method, ipset_datatype, extra_args=['-exist'])
    except FileNotFoundError:
        sys.exit("ipset command not found")

    try:
        temp_ipset_return = temp_ipset.create()
    except subprocess.CalledProcessError as e:
        sys.exit("Failed to create ipset: {}\n{}".format(e.args, e.stderr))

    # Get ip list to drop
    ip_list = blacklist_ips
    for u in droplist_urls:
        for ipl in sanitize_droplist(
                fetch_droplist(u), [';', '#'], add_whitelist_ips=whitelist_ips):
            if ipl not in ip_list:
                ip_list.append(ipl)

    try:
        temp_ipset.add_ips(ip_list)
    except subprocess.CalledProcessError as e:
        sys.exit("Failed to add ips to ipset: {}\n{}".format(e.args, e.stderr))

    """
    Create main ipset if doesn't exist
    ipset create ${name} hash:net -exist
    """
    try:
        ipset = Ipset(ipset_name, ipset_method, ipset_datatype, extra_args=['-exist'])
    except FileNotFoundError:
        sys.exit("ipset command not found")

    try:
        ipset_return = ipset.create()
    except subprocess.CalledProcessError as e:
        sys.exit("Failed to create ipset: {}\n{}".format(e.args, e.stderr))

    try:
        temp_ipset.swap(ipset.name)
    except subprocess.CalledProcessError as e:
        sys.exit("Failed to swap ipset: {}\n{}".format(e.args, e.stderr))

    # Destroy the temp ipset
    try:
        temp_ipset.destroy()
    except subprocess.CalledProcessError as e:
        sys.exit("Failed to destroy ipset: {}\n{}".format(e.args, e.stderr))

    print_verbose("Created ipset {} successfully".format(ipset_name), verbose)

    if not logger.disabled:
        ip_list_formatted = '\n'.join('\t{}'.format(k) for k in ip_list)
        logger.info("Blocked IP list: \n{}\n".format(ip_list_formatted))


if __name__ == "__main__":
    # execute only if run as a script
    main()
