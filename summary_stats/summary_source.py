
"""
hash_data reads a list of md5 hash strings and performs 2 Autofocus api
queries to get verdict/filetype and then signature coverage data
This provides contextual information in test environments beyond just a hash miss
"""
import sys
import time
import json
import requests
import calendar

from datetime import datetime
from af_api import api_key
from conf import hostname


# FIXME wait and retry when server connect errors happen vs ending program


def elk_index(elk_index_name):

    """
    set up elasticsearch bulk load index
    :param elk_index_name: name of data index in elasticsearch
    :return: index tag to write as line in the output json file
    """

    index_tag_full = {}
    index_tag_inner = {}
    index_tag_inner['_index'] = elk_index_name
    index_tag_inner['_type'] = elk_index_name
    index_tag_full['index'] = index_tag_inner

    return index_tag_full



def monthly_stats(sourcetype, startdate, enddate, verdict):


    if verdict is 'malware':
        afquery = {"operator":"all",
                 "children":[{"field":"sample.malware","operator":"is","value":1},
                             {"field": "session.upload_src", "operator": "is", "value": f"{sourcetype}"},
                             {"field":"sample.create_date","operator":"is in the range",
                                "value":[f"{startdate}T00:00:00",f"{enddate}T23:59:59"]},
                             ]}

    else:
        afquery = {"operator": "all",
                   "children": [
                                {"field": "session.upload_src", "operator": "is", "value": f"{sourcetype}"},
                                {"field": "sample.create_date", "operator": "is in the range",
                                   "value": [f"{startdate}T00:00:00", f"{enddate}T23:59:59"]},
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
    search_url = f'https://{hostname}/api/v1.0/samples/search'

    try:
        search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
        print('Search query posted to Autofocus')
        search.raise_for_status()
    except requests.exceptions.HTTPError:
        print(search)
        print(search.text)
        print('\nCorrect errors and rerun the application\n')
        sys.exit()

    search_dict = json.loads(search.text)

    return search_dict



def get_query_results(search_dict, startTime):

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
    index = 1

    running_total = []
    running_length = []
    all_sample_dict = {}
    all_sample_dict['samples'] = []

    while search_progress != 'FIN':

        time.sleep(5)
        try:
            results_url = f'https://{hostname}/api/v1.0/samples/results/' + cookie
            headers = {"Content-Type": "application/json"}
            results_values = {"apiKey": api_key}
            results = requests.post(results_url, headers=headers, data=json.dumps(results_values))
            results.raise_for_status()
        except requests.exceptions.HTTPError:
            print(results)
            print(results.text)
            print('\nCorrect errors and rerun the application\n')
            sys.exit()

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


            if autofocus_results['af_in_progress'] is False :
                search_progress = 'FIN'
        else:
            print('Autofocus still queuing up the search...')

    print(f"total hits: {autofocus_results['total']}")

    return autofocus_results['total']


def main():

    startyear = 2016
    currentyear = int(datetime.now().year)

    startTime = datetime.now()
    index = 1

    index_tag_full = elk_index('source_stats')

    stypes = [
        'Firewall',
        'Proofpoint',
        'Traps',
        'Magnifier',
        'Manual API',
        'Traps Android',
        'WF Appliance'
    ]

    for year in range(startyear, currentyear+1):
        for month in range(1, 13):

            if month < 10:
                cleanmonth = f'0{str(month)}'
            else:
                cleanmonth = str(month)

            weekday, endday = calendar.monthrange(year, month)

            if endday < 10:
                cleandendday = f'0{str(endday)}'
            else:
                cleanendday = str(endday)

            startdate = f'{year}-{cleanmonth}-01'
            enddate = f'{year}-{cleanmonth}-{cleanendday}'


            sdate = f'{year}-{cleanmonth}'

            monthly_count_dict = {}

            for type in stypes:

                print('=' * 80)
                print(f'starting search for {sdate} and type = {type}\n')

                print('getting malware verdict counts')
                # submit query and get results for malware verdict counts
                mal_query = monthly_stats(type, startdate, enddate, 'malware')
                mal_count = get_query_results(mal_query, startTime)
                mal_dailyavg = int(mal_count / endday)

                print('getting all verdict counts')
                # submit query and get results for all all verdict counts
                all_query = monthly_stats(type, startdate, enddate, 'all')
                all_count = get_query_results(all_query, startTime)
                all_dailyavg = int(all_count / endday)

                monthly_count_dict['date'] = sdate
                monthly_count_dict['upload_source'] = type
                monthly_count_dict['malware_monthly_count'] = mal_count
                monthly_count_dict['malware_daily_average'] = mal_dailyavg
                monthly_count_dict['all_verdict_monthly_count'] = all_count
                monthly_count_dict['all_verdict_daily_average'] = all_dailyavg

                if index == 1:
                    with open(f'upload_source_summary.json', 'w') as stat_file:
                        stat_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                        stat_file.write(json.dumps(monthly_count_dict, indent=None, sort_keys=False) + "\n")
                else:
                    with open(f'upload_source_summary.json', 'a') as stat_file:
                        stat_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                        stat_file.write(json.dumps(monthly_count_dict, indent=None, sort_keys=False) + "\n")

                index += 1


if __name__ == '__main__':
    main()
