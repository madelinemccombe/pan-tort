
"""
hash_data reads a list of md5 hash strings and performs 2 Autofocus api
queries to get verdict/filetype and then signature coverage data
This provides contextual information in test environments beyond just a hash miss
"""
import sys
import os
import time
import json
import requests
import calendar
import csv

import conf
from datetime import datetime
from af_api import api_key


def output_dir(dir_name):

    '''
    check for the output dirs and if exist=False then create them
    :param dir_name: directory name to be check and possibly created
    '''

    # check if the out_estack dir exists and if not then create it
    if os.path.isdir(dir_name) is False:
        os.mkdir(dir_name, mode=0o755)


def daily_stats(sourcetype, startdate, enddate):


    if sourcetype == 'no_API':
        afquery = {"operator":"all",
                 "children":[{"field":"sample.malware","operator":"is","value":1},
                             {"field":"sample.create_date","operator":"is in the range","value":[f"{startdate}T00:00:00",f"{enddate}T23:59:59"]},
                             {"field":"session.upload_src","operator":"is not","value":"Manual API"},]}

    elif sourcetype == 'API':
        afquery = {"operator":"all",
                 "children":[{"field":"sample.malware","operator":"is","value":1},
                             {"field":"sample.create_date","operator":"is in the range","value":[f"{startdate}T00:00:00",f"{enddate}T23:59:59"]},
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
            results_url = f'https://{conf.hostname}/api/v1.0/samples/results/' + cookie
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

    startyear = conf.start_year
    currentyear = int(datetime.now().year)

    startTime = datetime.now()

    #check for dir and create if needed
    output_dir(conf.out_json)

    headers = ['month', 'total_malware', 'total_daily_avg', 'noAPI_malware', 'noAPI_daily_avg']

    with open(f'{conf.out_csv}/monthly_malware_stats.csv', 'w') as statfile:
        writer = csv.writer(statfile)
        writer.writerow(headers)

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

            stypes = ['API', 'no_API']
            sdate = f'{year}-{cleanmonth}'

            csvlist = [sdate]

            for stype in stypes:

                print('=' * 80)
                print(f'starting search for {sdate} and type = {stype}')

                #submit bulk query for sample data to AF
                searchrequest = monthly_stats(stype, startdate, enddate)

                #get query results and parse output
                samplecount = get_query_results(searchrequest, startTime)

                dailyavg = int(samplecount / endday)

                csvlist.append(samplecount)
                csvlist.append(dailyavg)

            with open(f'{conf.out_csv}/monthly_malware_stats.csv', 'a') as statfile:
                writer = csv.writer(statfile)
                writer.writerow(csvlist)


if __name__ == '__main__':
    main()
