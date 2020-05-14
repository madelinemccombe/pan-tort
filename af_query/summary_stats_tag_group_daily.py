"""
hash_data reads a list of md5 hash strings and performs 2 Autofocus api
queries to get verdict/filetype and then signature coverage data
This provides contextual information in test environments beyond just a hash miss
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, date, timedelta
import requests
from http.client import RemoteDisconnected
from urllib3.exceptions import ProtocolError

import conf

# adding shared dir for imports
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(here, '../shared')))
# script to create or update the tagdata.json list from Autofocus
from gettagdata import tag_query


def output_dir(dir_name):
    '''
    check for the output dirs and if exist=False then create them
    :param dir_name: directory name to be check and possibly created
    '''

    # check if the out_estack dir exists and if not then create it
    if os.path.isdir(dir_name) is False:
        os.mkdir(dir_name, mode=0o755)


def daily_stats(tag_group, querydate, verdict, role, api_key):

    if verdict == 'malware' and role == 'standard':
        afquery = {"operator": "all",
                   "children": [{"field": "sample.malware", "operator": "is", "value": 1},
                                {"field": "session.upload_src", "operator": "is not", "value": "Manual API"},
                                {"field": "sample.tag_group", "operator": "is", "value": f"{tag_group}"},
                                {"field": "sample.create_date", "operator": "is in the range",
                                 "value": [f"{querydate}T00:00:00", f"{querydate}T23:59:59"]},
                                # temp addition due to data issue
                                {"field": "sample.tag", "operator": "is not in the list", "value": ["Unit42.VirLock"]}
                                ]}

    elif verdict == 'malware' and role == 'researcher':
        afquery = {"operator": "all",
                   "children": [{"field": "sample.malware", "operator": "is", "value": 1},
                                {"field": "session.upload_src", "operator": "is not", "value": "Manual API"},
                                {"field": "sample.tag_group", "operator": "is", "value": f"{tag_group}"},
                                {"field": "sample.create_date", "operator": "is in the range",
                                "value": [f"{querydate}T00:00:00", f"{querydate}T23:59:59"]},
                                {"field": "session.device_acctname", "operator": "does not contain", "value": "Palo"},
                                {"field": "session.device_acctname", "operator": "does not contain", "value": "palo"},
                                # temp addition due to data issue
                                {"field": "sample.tag", "operator": "is not in the list", "value": ["Unit42.VirLock"]}
                                ]}

    else:
        afquery = {"operator": "all",
                   "children": [
                       {"field": "sample.tag_group", "operator": "is", "value": f"{tag_group}"},
                       {"field": "sample.create_date", "operator": "is in the range",
                        "value": [f"{querydate}T00:00:00", f"{querydate}T23:59:59"]},
                   ]}

    print('Initiating query to Autofocus')
    search_values = {"apiKey": api_key,
                     "query": afquery,
                     "size": 50,
                     "scope": "global",
                     "from": 0,
                     "artifactSource": "af"
                     }

    headers = {"Content-Type": "application/json"}
    search_url = f'https://{conf.hostname}/api/v1.0/samples/search'

    good_search = False

    while good_search is False:
        try:
            search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
            print('Search query posted to Autofocus')
            search.raise_for_status()
            good_search = True
        except requests.exceptions.HTTPError:
            print(search)
            print(search.text)
            print('\nCorrect errors and rerun the application\n')
            sys.exit()
        except ProtocolError:
            print('kicked out early - protocol error - trying again')
        except requests.exceptions.ConnectionError:
            print('lost connection during initial query - trying again')
        except RemoteDisconnected:
            print('client disconnect error during initial query - trying again')

    search_dict = json.loads(search.text)

    return search_dict


def get_query_results(search_dict, startTime, api_key):
    """
    keep checking autofocus until a hit or search complete
    :param search_dict: initial response including the cookie value
    :return: autofocus search results dictionary or null if no hits
    """

    autofocus_results = {}

    cookie = search_dict['af_cookie']
    print(f'Tracking cookie is {cookie}')
    print('Getting sample data...\n')

    search_progress = 'start'
    #index = 1

    running_total = []
    running_length = []
    all_sample_dict = {}
    all_sample_dict['samples'] = []

    while search_progress != 'FIN':

        #time.sleep(5)
        good_search = False

        while good_search is False:
            try:
                results_url = f'https://{conf.hostname}/api/v1.0/samples/results/' + cookie
                headers = {"Content-Type": "application/json"}
                results_values = {"apiKey": api_key}
                results = requests.post(results_url, headers=headers, data=json.dumps(results_values))
                results.raise_for_status()
                good_search = True
            except requests.exceptions.HTTPError:
                print(results)
                print(results.text)
                print('\nCorrect errors and rerun the application\n')
                sys.exit()
            except ProtocolError:
                print('kicked out getting results due to disconnect')
                return None
            except requests.exceptions.ConnectionError:
                print('lost connection during get data query')
                return None
            except RemoteDisconnected:
                print('client disconnect error - should try again')
                return None

        autofocus_results = results.json()

        if 'total' in autofocus_results:

            running_total.append(autofocus_results['total'])
            running_length.append(len(autofocus_results['hits']))

            if autofocus_results['total'] != 0:
                # parse data and output estack json elements
                # return is running dict of all samples for pretty json output

                print(f'Results update\n')
                print(f"samples found so far: {autofocus_results['total']}")
                print(f"Search percent complete: {autofocus_results['af_complete_percentage']}%")
                minute_pts_rem = autofocus_results['bucket_info']['minute_points_remaining']
                daily_pts_rem = autofocus_results['bucket_info']['daily_points_remaining']
                print(f'AF quota update: {minute_pts_rem} minute points and {daily_pts_rem} daily points remaining')
                elapsedtime = datetime.now() - startTime
                print(f'Elasped run time is {elapsedtime}')
                print('-' * 80)

            if autofocus_results['af_in_progress'] is False:
                search_progress = 'FIN'
        else:
            print('Autofocus still queuing up the search...')
            # sleep delay to save AF quota points if search slow to start
            time.sleep(5)

    print(f"total hits: {autofocus_results['total']}")

    return autofocus_results['total']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--api_key", help="Autofocus API key", type=str)
    parser.add_argument("-r", "--role", help="Autofocus user role", type=str)
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()
        exit(1)

    api_key = args.api_key
    role = args.role

    # check for dir and create if needed
    output_dir(conf.out_json)

    # refresh tag group list
    if conf.gettagdata == 'yes':
        tag_query(api_key)

    # read group list and create tag_groups list
    tag_groups = []
    with open('data/groupList.txt', 'r') as groupFile:
        for group in groupFile:
            if group != '\n':
                tag_groups.append(group.rstrip())

    print('tag group list created')

    # start and end year, month, and day for the capture
    # interval is number of days per query
    start_date = date(conf.start_year, conf.start_month, conf.start_day)
    end_date = date(conf.end_year, conf.end_month, conf.end_day)
    day = timedelta(days=conf.date_interval)

    index = 1
    startTime = datetime.now()
    query_date = start_date

    while query_date <= end_date:

        print(f'working with date: {query_date}')

        daily_count_dict = {}

        # create elk index by month and year
        index_tag_full = {}
        index_tag_inner = {}
        elk_index_name = f"tag_group_stats_daily-{query_date.year}-{query_date.strftime('%m')}"
        index_tag_inner['_index'] = f'{elk_index_name}'
        index_tag_inner['_type'] = f'{elk_index_name}'
        index_tag_full['index'] = index_tag_inner

        for tag_group in tag_groups:
            time.sleep(5)
            print('=' * 80)
            print(f'starting search for {query_date} and tag_group = {tag_group}\n')

            print('getting malware verdict counts')
            # submit query and get results for malware verdict counts

            mal_count = None

            while mal_count is None:
                mal_query = daily_stats(tag_group, query_date, 'malware', role, api_key)
                mal_count = get_query_results(mal_query, startTime, api_key)

            daily_count_dict['date'] = str(query_date)
            daily_count_dict['metrics.threat.tag.group.name'] = tag_group
            daily_count_dict['metrics.threat.tag.group.count'] = mal_count

            if index == 1:
                with open(f'{conf.out_json}/tag_group_daily_summary_{start_date}_{end_date}.json', 'w') as stat_file:
                    stat_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                    stat_file.write(json.dumps(daily_count_dict, indent=None, sort_keys=False) + "\n")
            else:
                with open(f'{conf.out_json}/tag_group_daily_summary_{start_date}_{end_date}.json', 'a') as stat_file:
                    stat_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                    stat_file.write(json.dumps(daily_count_dict, indent=None, sort_keys=False) + "\n")

            index += 1

        query_date += day

    # print out the elasticSearch bulk load curl commands
    print('\nUse curl -XDELETE [url]:[port]/index to delete data from the index')
    print('use the XPOST curl command to load json data to elasticSearch')
    print('add -u with username:password if security features enabled\n')

    print(
        f'curl -s -XPOST \'http://{conf.elastic_url_port}/_bulk\' --data-binary @{conf.out_json}/tag_group_daily_summary_{start_date}_{end_date}.json -H \"Content-Type: application/x-ndjson\" \n')

if __name__ == '__main__':
    main()
