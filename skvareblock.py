import urllib.request

firewall_ipset = "blockipset"

never_block = ['127.0.0.0', '127.0.0.1', '0.0.0.0']

droplist_urls = [
    'https://www.spamhaus.org/drop/drop.txt',
    'https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt'
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
        if ip_line.strip() and not any(nb in ip_line for nb in never_block):
            sanitized_ips.append(ip_line)

    return sanitized_ips


def fetch_droplist(url: str) -> list:

    response = urllib.request.urlopen(url)
    data = response.read()
    return data.decode('utf-8').split('\n')


def main():
    ip_list = []

    for u in droplist_urls:
        ip_list.extend(
            sanitize_droplist(fetch_droplist(u), [';', '#']))

    for ip in ip_list:
        print(ip)


if __name__ == "__main__":
    # execute only if run as a script
    main()
