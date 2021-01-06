import settings as s
import sys
import requests
import pandas as pd
import argparse
import json
import ipaddress


def get_ipv4_list(multi_ips):

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

    ip_list = []

    net = ipaddress.ip_network(single_ip, strict=False)

    for n in net:
        ipv4 = format(ipaddress.IPv4Address(n))

        ip_list.append(ipv4)

    return ip_list


def aipdb_query(ips, apikey, time):

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

    df['AbuseIPDB Link'] = 'https://abuseipdb.com/check'+df['ipAddress']
    return df


def create_csv(df, filename):
    print('Creating CSV...')
    filename = str(filename)
    report = df.to_csv(filename, index=True)
    print('Report saved to ' + filename)
    return report


def main():

    # Arguments

    parser = argparse.ArgumentParser(description='Checks AbuseIPDB for IP reputation.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l', '--list', help='specify a list of IP addresses / CIDR from a file (one IP per line)')
    group.add_argument('-i', '--ip', help='specify a single IP or CIDR to query')

    parser.add_argument('-o', '--output', help='Output file. Select filename and path for results csv', required=True)
    parser.add_argument('-d', '--days', type=int, default=180, help='Specify how many days to check. Max limit 365 days. Default is 180 days.' )

    args = parser.parse_args()

    iplist = args.list
    ip = args.ip
    savefile = args.output
    days = args.days

    # Check for API Key

    if s.aipdb_key == None:
        print('Abuse IPDB API key is not present in .env file. Exiting.')
        sys.exit()
    else:
        key = s.aipdb_key

    if days > 365:
        print('You have specified a date range in excess of the AbuseIPDB 365 day limit. Select a shorter date range or leave blank.')
        sys.exit()

    if args.ip:
        ips = get_ipv4(ip)
        aipdb_response = aipdb_query(ips, key, days)
        create_csv(aipdb_response, savefile)

    if args.list:
        ips = get_ipv4_list(iplist)
        aipdb_response = aipdb_query(ips, key, days)
        create_csv(aipdb_response, savefile)


main()




