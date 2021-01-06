import settings as s
import sys
import requests
import pandas as pd
import argparse
import json
import ipaddress


def get_ipv4_list(multi_ips):
    """Formats IP addresses inputted as a list. Converts CIDR to list of single IPs"""

    ip_list = []

    with open(multi_ips, 'r') as f:
        lines = [line.strip() for line in f.readlines()]
        lines = [x for x in lines if x]

    for i in lines:
        net = ipaddress.ip_network(i, strict=False)

        for n in net:
            ipv4 = format(ipaddress.IPv4Address(n))

            ip_list.append(ipv4)

    return ip_list


def get_ipv4(single_ip):
    """Takes single IP or converts CIDR to list of IPs for query"""

    ip_list = []

    net = ipaddress.ip_network(single_ip, strict=False)

    for n in net:
        ipv4 = format(ipaddress.IPv4Address(n))

        ip_list.append(ipv4)

    return ip_list


def aipdb_query(ips, apikey, time):
    """Queries AbuseIPDB for all IPs passed, selects fields and converts to dataframe"""

    source_ips = ips
    appended_data = []

    print("Performing AbuseIPDB lookup...")

    try:
        for i in source_ips:

            url = 'https://api.abuseipdb.com/api/v2/check'

            querystring = {
                'ipAddress': str(i),
                'maxAgeInDays': str(time)
            }

            headers = {
                'Accept': 'application/json',
                'Key': str(apikey)
            }

            response = requests.request(method='GET', url=url, headers=headers, params=querystring)

            print('Querying AbuseIPDB for IP address ' + str(i))

            decodedResponse = json.loads(response.text)
            appended_data.append(decodedResponse['data'])

    except Exception as e:
        print('Error %s' % e)

    df = pd.DataFrame(appended_data)

    df = df[['ipAddress', 'lastReportedAt', 'abuseConfidenceScore', 'totalReports', 'isp', 'domain']]

    df['AbuseIPDB Link'] = 'https://abuseipdb.com/check/'+df['ipAddress']
    return df


def create_csv(df, filename):
    """Converts Dataframe to CSV"""
    print('Creating CSV...')
    filename = str(filename)
    report = df.to_csv(filename, index=True)
    print('Report saved to ' + filename)
    return report


def main():

    # Arguments

    parser = argparse.ArgumentParser(description='Checks AbuseIPDB for IP reputation.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l', '--list', help='specify a list of IP addresses / CIDR from a file (one IP per line). '
                                            'Use -d flag for optional time parameter')
    group.add_argument('-i', '--ip', help='specify a single IP or CIDR to query')

    parser.add_argument('-o', '--output', help='Output file. Select filename and path for results csv', required=True)
    parser.add_argument('-d', '--days', type=int, default=180, help='Specify how many days to check. '
                                                                    'Max limit 365 days. '
                                                                    'Default is 180 days.' )

    args = parser.parse_args()

    iplist = args.list
    ip = args.ip
    savefile = args.output
    days = args.days

    # Check for API Key in .env

    if s.aipdb_key == None:
        print('Abuse IPDB API key is not present in .env file. Exiting.')
        sys.exit()
    else:
        key = s.aipdb_key

    # Ensures date parameter does not exceed AIPDB's limit of last 365 days

    if days > 365:
        print('You have specified a date range in excess of the AbuseIPDB 365 day limit. '
              'Select a shorter date range or leave blank.')
        sys.exit()

    # Performs queries and saves results to CSV according to whether input is from a list or single entry.

    if args.ip:
        ips = get_ipv4(ip)
        aipdb_response = aipdb_query(ips, key, days)
        create_csv(aipdb_response, savefile)

    if args.list:
        ips = get_ipv4_list(iplist)
        aipdb_response = aipdb_query(ips, key, days)
        create_csv(aipdb_response, savefile)


main()




