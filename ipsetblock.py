#!/usr/bin/env python3

import argparse
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
import json
import logging
import os
import tempfile
import zipfile
from logging.handlers import RotatingFileHandler
from datetime import datetime

"""
ipsetblock allows easy creation of ipsets from block lists
"""

logger = None


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

    def add_ips(self, ips: list, extra_args=None):
        arguments = ['ipset', 'add', self.name]

        if extra_args:
            arguments.extend(extra_args)

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


class BlockList:
    time_format: str = '%Y-%m-%d %H:%M:%S'

    def __init__(self, name: str, url: str, data_type: str, comment: str,
                 update: str="always", lastfetch=None, is_file=False):
        self.name = name
        self.url = url
        self.is_file = is_file
        self.data_type = data_type
        self.comment = comment
        self.block_list = []
        self.update = update
        self.lastfetch = lastfetch

    def is_update_time(self):

        if not self.lastfetch:
            return True

        lastrun = datetime.strptime(self.lastfetch, self.time_format)

        difference = lastrun - datetime.now()

        if self.update == 'daily' and difference.days >= 1:
            return True
        elif self.update == 'hourly' and difference.min >= 60:
            return True
        elif self.update == 'minute' and difference.min >= 1:
            return True
        elif self.update == 'always':
            return True
        else:
            return False

    def fetch(self):

        if self.is_file:
            self.block_list.extend(
                self.sanitize(get_lines(self.url)))
            self.lastfetch = datetime.now().strftime(self.time_format)
            logger.info("Fetched '{}'".format(self.name))
            return self.block_list

        with tempfile.NamedTemporaryFile(delete=False) as tf, tempfile.TemporaryDirectory() as td:
            """
            Download file to tempfile
            """
            try:
                with urllib.request.urlopen(self.url) as in_stream:
                    shutil.copyfileobj(in_stream, tf)
            except urllib.error.URLError:
                raise

            if self.data_type == "zip":
                with zipfile.ZipFile(tf.name, "r") as zip_ref:
                    zip_ref.extractall(td)
                    ip_files = [os.path.join(td, nf) for nf in os.listdir(td)]
            elif self.data_type == "text":
                ip_files = [os.path.join(td, tf.name)]
            else:
                raise ValueError

            if ip_files:
                self.block_list.extend(
                    self.sanitize([g for l in ip_files for g in get_lines(l)]))

        self.lastfetch = datetime.now().strftime(self.time_format)
        logger.info("Fetched '{}'".format(self.name))
        return self.block_list

    def sanitize(self, ips: list) -> list:
        """
        Check if a comment character exist in an IP line and
        remove everything the comment.
        Return the list of sanitized IP addresses in a list with blank lines removed
        """
        sanitized_ips = []

        for ip in ips:
            if self.comment and self.comment in ip:
                ip_line = ip.split(self.comment)[0].strip()
            else:
                ip_line = ip.strip()

            if ip_line:
                sanitized_ips.append(ip_line)

        return sanitized_ips


class IpsetConfig:
    def __init__(self, name: str, family: str, method: str, datatype: str, blocklists: list,
                 blacklist_ips: list, whitelist_ips: list, last_run_data: dict):
        self.name = name
        self.family = family
        self.method = method
        self.datatype = datatype
        self.blocklists = blocklists
        self.blacklist_ips = blacklist_ips
        self.whitelist_ips = whitelist_ips
        self.blocked_ips = [b for b in self.blacklist_ips if b not in self.whitelist_ips]

        lrd = {}
        if last_run_data and 'ipsets' in last_run_data:
            lrd = next((d for d in last_run_data['ipsets'] if self.name in d), None)
            logger.info("Using last run data")

        self.ipset_data = lrd

    def get_ip_list(self):
        for b in self.blocklists:
            add_ips = []
            if b.is_update_time():
                try:
                    b.fetch()
                except urllib.error.HTTPError as e:
                    logger.info("Cannot fetch '{}' from '{}'\nerror: {}".format(b.name, b.url, e))
                    if self.ipset_data:
                        if 'blocklists' in self.ipset_data:
                            if b.name in self.ipset_data['blocklists']:
                                add_ips = self.ipset_data['blocklists']
                else:
                    add_ips = b.block_list
                    logger.info("Fetched '{}' from '{}'".format(b.name, b.url))
            else:
                logger.info("Isn't update time for,'{}' using old data if exists".format(b.name))
                if self.ipset_data:
                    if 'blocklists' in self.ipset_data:
                        if b.name in self.ipset_data['blocklists']:
                            add_ips = self.ipset_data['blocklists']

            self.blocked_ips.extend(
                [ip for ip in add_ips for wip in self.whitelist_ips if wip not in ip])


def print_verbose(message: str, verbose: bool):
    if verbose:
        print(message)


def get_logger(log_file: str, disable_logs: bool = False):

    log_formatter = logging.Formatter(
        '%(asctime)s %(message)s')

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


def fetch_old_data(file: str):
    try:
        with open(file) as data_file:
            config = json.load(data_file)
    except (IOError, FileNotFoundError):
        return None

    if 'ipsets' not in config:
        log_exit("{}: Key '{}' required in config".format('ipsets', file))

    for ip_set in config['ipsets']:
        required_keys = ['name', 'family', 'method', 'datatype']
        for v in required_keys:
            if v not in ip_set:
                log_exit("Key '{}' required in each ipset".format(v, file))

        if 'blocklists' in ip_set:
            for s in ip_set['blocklists']:
                required_keys = ['name', 'url', 'data_type', 'update']
                for k in required_keys:
                    if k not in s:
                        log_exit("{}: Key '{}' required in each blocklist".format(k, file))

                if 'blocked_ips' not in s:
                    s['blocked_ips'] = []

                if 'lastfetch' not in s:
                    s['lastfetch'] = None

    return config


def fetch_config(file: str="config.json"):
    try:
        with open(file) as config_file:
            config = json.load(config_file)
    except (IOError, FileNotFoundError):
        return None
    else:
        if 'ipsets' not in config:
            log_exit("{}: Key '{}' required in config".format('ipsets', file))

        for ip_set in config['ipsets']:
            required_keys = ['name', 'family', 'method', 'datatype']
            for v in required_keys:
                if v not in ip_set:
                    log_exit("{}: Key '{}' required in each ipset".format(v, file))

            if 'ips' not in ip_set:
                ip_set['ips'] = {"blacklisted": [], "whitelisted": []}

            if 'blocklists' in ip_set:
                for s in ip_set['blocklists']:
                    required_keys = ['name', 'data_type']
                    for k in required_keys:
                        if k not in s:
                            log_exit("{}: Key '{}' required in each blocklist".format(k, file))

                    if 'comment' not in s:
                        s['comment'] = ""

                    if 'url' not in s and 'file' not in s:
                        log_exit("{}: Key 'url' or 'file' required in each blocklist".format(file))

                    if 'url' in s and 'file' in s:
                        log_exit("{}: Key 'url' and 'file' cannot both be in a blocklist".format(
                            file))

        return config


def get_lines(filename: str) -> list:
    try:
        with open(filename) as f:
            lines = f.readlines()
    except FileNotFoundError:
        raise

    return lines


def temp_ipset(ipset_name: str, ipset_method: str, ipset_datatype: str, ipset_family: str,
               ips: list):

    """
    Create a temporary ipset
    ipset create ${name} hash:net -exist
    """
    temp_set = None
    try:
        temp_set = Ipset(
            "temp_{}".format(ipset_name), ipset_method, ipset_datatype,
            extra_args=['-exist', "family", ipset_family])
    except FileNotFoundError:
        log_exit("ipset command not found")

    try:
        temp_set.create()
    except subprocess.CalledProcessError as e:
        log_exit("Failed to create ipset: {}\n{}".format(e.args, e.stderr))

    try:
        temp_set.add_ips(ips, extra_args=['-exist'])
    except subprocess.CalledProcessError as e:
        log_exit("Failed to add ips to ipset: {}\n{}".format(e.args, e.stderr))

    return temp_set


def real_ipset_swap(temp_set: Ipset,
                    ipset_name: str, ipset_method: str, ipset_datatype: str, ipset_family: str):

    """
    Create main ipset if doesn't exist
    ipset create ${name} hash:net -exist
    """
    ipset = None
    try:
        ipset = Ipset(ipset_name, ipset_method, ipset_datatype,
                      extra_args=['-exist', "family", ipset_family])
    except FileNotFoundError:
        log_exit("ipset command not found")

    try:
        ipset_return = ipset.create()
    except subprocess.CalledProcessError as e:
        sys.exit("Failed to create ipset: {}\n{}".format(e.args, e.stderr))

    try:
        temp_set.swap(ipset.name)
    except subprocess.CalledProcessError as e:
        log_exit("Failed to swap ipset: {}\n{}".format(e.args, e.stderr))

    return ipset


def ipset_setup_set(ip_set: IpsetConfig):

    temp_set = temp_ipset(
        ip_set.name, ip_set.method, ip_set.datatype, ip_set.family, ip_set.blocked_ips)
    new_set = real_ipset_swap(temp_set, ip_set.name, ip_set.method, ip_set.datatype, ip_set.family)

    # Destroy the temp ipset
    try:
        temp_set.destroy()
    except subprocess.CalledProcessError as e:
        log_exit("Failed to destroy ipset: {}\n{}".format(e.args, e.stderr))

    return new_set


def log_exit(msg: str):
    logger.info(msg)
    sys.exit(msg)


def save_data(run_data: dict, file: str):
    with open(file, 'w+') as f:
        json.dump(run_data, f, ensure_ascii=False, sort_keys=True, indent=4)


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-v', '--verbose', action='store_true')

    parser.add_argument('-c', '--configfile', default="config.json")
    parser.add_argument('-d', '--datafile', default="data.json")

    parser.add_argument('-l', '--logfile', default="ipsetblock.log")
    args = parser.parse_args()

    return args


def main():
    args = parse_arguments()

    verbose = args.verbose

    configfile = args.configfile
    data_file = args.datafile

    logfile = args.logfile

    global logger
    logger = get_logger(logfile)

    config = fetch_config(configfile)

    if not config:
        log_exit("No config file '{}' found".format(configfile))
    logger.info("Found config:\n{}".format(config))

    data = fetch_old_data(data_file)

    if not data:
        logger.info("No data file '{}' found".format(data_file))
        data = {}
    logger.info("Found old datafile:\n{}".format(data_file))

    run_data = {"ipsets": []}

    # Get ip list to drop
    for ip_set in config['ipsets']:
        block_list = []
        if 'blocklists' in ip_set:
            for b in ip_set['blocklists']:
                if 'blocklists' in ip_set:
                    if 'url' in b:
                        url = b['url']
                        is_file = False
                    else:
                        url = b['file']
                        is_file = True

                    if 'update' in b:
                        update = b['update']
                    else:
                        update = "always"
                    block_list.append(BlockList(b['name'], url, b['data_type'], b['comment'],
                                                update=update, is_file=is_file))
        new_set = IpsetConfig(ip_set['name'], ip_set['family'], ip_set['method'],
                              ip_set['datatype'], block_list, ip_set['ips']['blacklisted'],
                              ip_set['ips']['whitelisted'], data)

        new_set.get_ip_list()

        run_data['ipsets'].append({
            "name": new_set.name,
            "family": new_set.family,
            "method": new_set.method,
            "datatype": new_set.datatype,
            "blocklists": [vars(b) for b in new_set.blocklists]
        })

        ipset_setup_set(new_set)

    save_data(run_data, data_file)


if __name__ == "__main__":
    # execute only if run as a script
    main()
