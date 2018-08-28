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

    def __init__(self, name, method, data_type, extra_args=None):
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

        logger.info(arguments)

        try:
            ipset = subprocess.check_output(arguments)
        except subprocess.CalledProcessError:
            raise

        return ipset

    def add_ips(self, ips, extra_args=None):
        arguments = ['ipset', 'add', self.name]

        if extra_args:
            arguments.extend(extra_args)

        for ip in ips:
            # logger.info(arguments + [ip])
            try:
                subprocess.check_output(arguments + [ip])
            except subprocess.CalledProcessError:
                raise

    def swap(self, swap_ipset):
        """
        swap the ipset
        """
        arguments = ['ipset', 'swap', self.name, swap_ipset]
        logger.info(arguments)

        try:
            subprocess.check_output(arguments)
        except subprocess.CalledProcessError:
            raise

    def destroy(self):
        """
        Destroy the ipset
        """
        arguments = ['ipset', 'destroy', self.name]

        logger.info(arguments)

        try:
            subprocess.check_output(arguments)
        except subprocess.CalledProcessError:
            raise


class BlockList:
    time_format = '%Y-%m-%d %H:%M:%S'

    def __init__(self, name, url, data_type, comment,
                 update="always", lastfetch=None, is_file=False):
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

        difference = datetime.strptime(self.lastfetch, self.time_format) - datetime.now()

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
            try:
                lines = get_lines(self.url)
            except FileNotFoundError as e:
                log_exit("{} {}".format(e.strerror, self.url))
            self.block_list.extend(self.sanitize(lines))
            self.lastfetch = datetime.now().strftime(self.time_format)
            logger.info("Fetched '{}'".format(self.name))
            return self.block_list

        if self.data_type == "zip":
            self.block_list.extend(
                self.sanitize(get_lines_from_archive(self.data_type, self.url)))

        elif self.data_type == "text":
            with urllib.request.urlopen(self.url) as r:
                data = r.read()
            self.block_list.extend(self.sanitize(data.decode('utf-8').split('\n')))

        else:
            raise ValueError

        self.lastfetch = datetime.now().strftime(self.time_format)
        # logger.info("Fetched '{}' ips:\n{}".format(self.name, "\n".join(self.block_list)))
        return self.block_list

    def sanitize(self, ips):
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
                # logger.info("Sanitized: {} -> {}".format(ip, ip_line))
                sanitized_ips.append(ip_line)

        return sanitized_ips


class IpsetConfig:
    def __init__(self, name, family, method, datatype, blocklists,
                 blacklist_ips, whitelist_ips, last_run_data, saveto=None):
        self.name = name
        self.family = family
        self.method = method
        self.datatype = datatype
        self.blocklists = blocklists
        self.blacklist_ips = blacklist_ips
        self.whitelist_ips = whitelist_ips
        self.blocked_ips = [b for b in self.blacklist_ips if b not in self.whitelist_ips]
        self.saveto = saveto

        logger.info("Created IpsetConfig with ips: {}".format(self.blocked_ips))

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

            for ip in add_ips:
                if ip not in self.whitelist_ips:
                    self.blocked_ips.append(ip)

        if self.saveto:
            try:
                with open(self.saveto, "w") as sf:
                    sf.write("{}\n".format("\n".join(self.blocked_ips)))
            except PermissionError as e:
                log_exit("Failed saving to {}, {}".format(self.saveto, e.strerror))


def get_lines_from_archive(file_type, url):
    lines = []
    with tempfile.NamedTemporaryFile(delete=False) as tf, tempfile.TemporaryDirectory() as td:
        """
        Download file to tempfile
        """

        try:
            with urllib.request.urlopen(url) as in_stream:
                shutil.copyfileobj(in_stream, tf)
        except urllib.error.URLError:
            raise

        if file_type == "zip":
            with zipfile.ZipFile(tf.name, "r") as zip_ref:
                zip_ref.extractall(td)
                ip_files = [os.path.join(td, nf) for nf in os.listdir(td)]
                lines.extend([g for l in ip_files for g in get_lines(l)])

    return lines


def print_verbose(message, verbose: bool):
    if verbose:
        print(message)


def get_logger(log_file, disable_logs=False):

    log_formatter = logging.Formatter('%(asctime)s %(message)s')

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


def fetch_old_data(file):
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


def fetch_config(file="config.json"):
    try:
        with open(file) as config_file:
            try:
                config = json.load(config_file)
            except json.decoder.JSONDecodeError as e:
                log_exit("Problem with json config: {}".format(e))
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

            if 'saveto' not in ip_set:
                ip_set['saveto'] = None

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


def get_lines(filename):
    try:
        with open(filename) as f:
            lines = f.readlines()
    except FileNotFoundError:
        raise

    return lines


def temp_ipset(ipset_name, ipset_method, ipset_datatype, ipset_family, ips):

    """
    Create a temporary ipset
    ipset create ${name} hash:net -exist
    """

    # So list doesn't overflow
    ip_len = len(ips)
    maxelem = str(ip_len + (ip_len // 4))

    temp_set = None
    try:
        temp_set = Ipset(
            "temp_{}".format(ipset_name), ipset_method, ipset_datatype,
            extra_args=['-exist', "family", ipset_family, "maxelem", maxelem])
    except FileNotFoundError:
        log_exit("ipset command not found")

    try:
        temp_set.create()
    except subprocess.CalledProcessError as e:
        log_exit("Failed to create ipset: {}".format(e.args))

    try:
        temp_set.add_ips(ips, extra_args=['-exist'])
    except subprocess.CalledProcessError as e:
        log_exit("Failed to add ips to ipset: {}".format(e.args))

    return temp_set


def real_ipset_swap(temp_set: Ipset,
                    ipset_name, ipset_method, ipset_datatype, ipset_family):

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
        sys.exit("Failed to create ipset: {}".format(e.args))

    try:
        temp_set.swap(ipset.name)
    except subprocess.CalledProcessError as e:
        try:
            temp_set.destroy()
        except subprocess.CalledProcessError:
            pass
        log_exit("Failed to swap ipset: {}".format(e.args))
    logger.info("Swapped ipset {} for {}".format(temp_set.name, ipset_name))

    return ipset


def ipset_setup_set(ip_set):

    temp_set = temp_ipset(
        ip_set.name, ip_set.method, ip_set.datatype, ip_set.family, ip_set.blocked_ips)
    new_set = real_ipset_swap(temp_set, ip_set.name, ip_set.method, ip_set.datatype, ip_set.family)

    # Destroy the temp ipset
    try:
        temp_set.destroy()
    except subprocess.CalledProcessError as e:
        log_exit("Failed to destroy ipset: {}".format(e.args))

    logger.info("Finished ipset setup for {} with {} ips".format(
        ip_set.name, len(ip_set.blocked_ips)))

    return new_set


def log_exit(msg):
    logger.info(msg)
    sys.exit(msg)


def save_data(run_data, file):
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
                              ip_set['ips']['whitelisted'], data, saveto=ip_set['saveto'])

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
