####!/usr/bin/env python3
"""
hash_data reads a list of md5 hash strings and performs 2 Autofocus api
queries to get verdict/filetype and then signature coverage data
This provides contextual information in test environments beyond just a hash miss
"""
import sys
import json
import time
from datetime import timedelta, datetime
import requests

from panrc import hostname, api_key, threatnamefile, hashtype, index_name


def init_hash_counters():

    """
    Use counters to create a simple output stats file in tandem with json details
    Initialize counters to zero
    """

    hash_counters = {}
    hash_count_values = ['total samples', 'malware', 'mal_inactive_sig', 'mal_active_sig',
                         'mal_no_sig', 'grayware', 'benign', 'phishing', 'No sample found',
                         'sig_new', 'sig_updated']

    for value in hash_count_values:
        hash_counters[value] = 0

    return hash_counters


def elk_index(elk_index_name, index):

    """ Index setup for ELK Stack bulk install """

    index_tag_full = {}
    index_tag_inner = {}
    index_tag_inner['_index'] = elk_index_name
    index_tag_inner['_type'] = elk_index_name
    index_tag_inner['_id'] = index
    index_tag_full['index'] = index_tag_inner

    return index_tag_full


def get_threatname_list(filename):

    """ read the threatname list from file and load into a list """

    threatname_list = []

    with open(filename, 'r') as threatname_file:
        threatname_list = threatname_file.read().splitlines()

    return threatname_list


def init_query(af_ip, af_api_key, threatname):

    """
    initial API query post to Autofocus
    get_query_results used to check status and read query results
    """

    query = {"operator": "all",
             "children": [{"field":"sample.threat_name", "operator":"is", "value":threatname}]
            }

    search_values = {"apiKey": af_api_key,
                     "query": query,
                     "size": 1,
                     "from": 0,
                     "sort": {"create_date": {"order": "desc"}},
                     "scope": "public",
                     "artifactSource": "af"
                    }

    headers = {"Content-Type": "application/json"}
    search_url = f'https://{af_ip}/api/v1.0/samples/search'

    try:
        search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
        print('Search query posted to Autofocus')
        search.raise_for_status()
    except requests.exceptions.HTTPError:
        print(search)
        print(search.text)
        print('\nCorrect errors and rerun the application\n')
        sys.exit()

    search_dict = {}
    search_dict = json.loads(search.text)

    return search_dict


def get_query_results(af_ip, af_api_key, search_dict):

    """ check for a hit and then retrieve search results when hit = 1 """

    autofocus_results = {}

    cookie = search_dict['af_cookie']
    print(f'Tracking cookie is {cookie}')
    query_status = ''

    while query_status != 'FIN':

        time.sleep(3)
        try:
            results_url = f'https://{af_ip}/api/v1.0/samples/results/' + cookie
            headers = {"Content-Type": "application/json"}
            results_values = {"apiKey": af_api_key}
            results = requests.post(results_url, headers=headers, data=json.dumps(results_values))
            results.raise_for_status()
        except requests.exceptions.HTTPError:
            print(results)
            print(results.text)
            print('\nCorrect errors and rerun the application\n')
            sys.exit()

        autofocus_results = results.json()

        if 'total' in autofocus_results:
            if autofocus_results['total'] == 0:
                print('Now waiting for a hit...')
            else:
                query_status = 'FIN'
        else:
            print('Autofocus still queuing up the search...')

    return autofocus_results


def get_sample_data(af_ip, af_api_key, threatname, hash_counters):

    """ query each hash to get malware verdict and associated data """

    malware_values = {'0': 'benign', '1': 'malware', '2': 'grayware', '3': 'phishing'}


    hash_data_dict = {}
    print(f'\nworking with threat_name = {threatname}')

    search_dict = init_query(af_ip, af_api_key, threatname)
    autofocus_results = get_query_results(af_ip, af_api_key, search_dict)


# AFoutput is json output converted to python dictionary

    hash_data_dict['threatname'] = threatname

    if autofocus_results['hits']:

# initial AF query to get sample data include sha256 hash and WF verdict

        verdict_num = autofocus_results['hits'][0]['_source']['malware']
        verdict_text = malware_values[str(verdict_num)]
        hash_data_dict['verdict'] = verdict_text
        hash_data_dict['filetype'] = autofocus_results['hits'][0]['_source']['filetype']
        hash_data_dict['sha256hash'] = autofocus_results['hits'][0]['_source']['sha256']
        hash_data_dict['create_date'] = autofocus_results['hits'][0]['_source']['create_date']
        if 'tag' in autofocus_results['hits'][0]['_source']:
            hash_data_dict['tag'] = autofocus_results['hits'][0]['_source']['tag']
        print(f'Hash verdict is {verdict_text}')

        hash_counters[verdict_text] += 1

# If no hash found then tag as 'no sample found'
# These hashes can be check in VirusTotal to see if unsupported file type for Wildfire
    else:
        hash_data_dict['verdict'] = 'No sample found'
        print('\n     No public sample found in Autofocus for this threatname')
        verdict_text = 'No sample found'

    return hash_data_dict


def get_sig_coverage(af_ip, af_api_key, sample_data, hash_counters):

    """ for sample hits, second query to find signature coverage in sample analysis """

    print('Searching Autofocus for current signature coverage...')

    search_values = {"apiKey": af_api_key,
                     "coverage": 'true',
                     "sections": ["coverage"],
                    }

    headers = {"Content-Type": "application/json"}
    hashvalue = sample_data['sha256hash']
    search_url = f'https://{af_ip}/api/v1.0/sample/{hashvalue}/analysis'

    try:
        search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
        search.raise_for_status()
    except requests.exceptions.HTTPError:
        print(search)
        print(search.text)
        print('\nCorrect errors and rerun the application\n')
        sys.exit()

    results_analysis = {}
    results_analysis = json.loads(search.text)
    sample_data['sig_create_date'] = results_analysis['coverage']['wf_av_sig'][0]['create_date']
    sample_data['sig_first_added'] = results_analysis['coverage']['wf_av_sig'][0]['first_added_daily']
    sample_data['sig_last_added'] = results_analysis['coverage']['wf_av_sig'][0]['last_added_daily']
    sample_data['dns_sig'] = results_analysis['coverage']['dns_sig']
    sample_data['wf_av_sig'] = results_analysis['coverage']['wf_av_sig']
    sample_data['fileurl_sig'] = results_analysis['coverage']['fileurl_sig']

# get time delta between new sample and new sig in minutes
    sample_FMT = '%Y-%m-%dT%H:%M:%S'
    sig_FMT = '%Y-%m-%d %H:%M:%S'    
    sig_time = datetime.strptime(sample_data['sig_create_date'], sig_FMT)
    sample_time = datetime.strptime(sample_data['create_date'], sample_FMT)
    tdelta = sig_time - sample_time
    tdelta_minutes = round(tdelta.total_seconds() / 60, 1)
    sample_data['create_delta'] = str(tdelta)
    sample_data['create_delta_minutes'] = tdelta_minutes

# Check all the sig states [true or false] to see active vs inactive sigs for malware

    if sample_data['verdict'] == 'malware':
        sig_search = json.dumps(sample_data)
        if sig_search.find('true') != -1:
            hash_counters['mal_active_sig'] += 1
        elif sig_search.find('true') == -1 and sig_search.find('false') != -1:
            hash_counters['mal_inactive_sig'] += 1
        else:
            hash_counters['mal_no_sig'] += 1

    if sample_data['sig_first_added'] == sample_data['sig_last_added']:
        sample_data['sig_type'] = 'new'
        hash_counters['sig_new'] += 1
    else:
        sample_data['sig_type'] = 'updated'
        hash_counters['sig_updated'] += 1

    return sample_data, hash_counters


def write_to_file(index, index_tag_full, hash_data_dict, hash_counters):

    """
    write hash data to text file; for index = 1 create new file; for index > 1 append to file
    hash_data_estack uses the non-pretty format with index to bulk load into ElasticSearch
    hash_data_pretty has readable formatting to view the raw hash context data
    """

    if index == 1:
        with open('threatname_data_estack.json', 'w') as output_file:
            output_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
            output_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

        with open('threatname_data_pretty.json', 'w') as output_file:
            output_file.write(json.dumps(hash_data_dict, indent=4, sort_keys=False) + "\n")

    else:
        with open('threatname_data_estack.json', 'a') as output_file:
            output_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
            output_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

        with open('threatname_data_pretty.json', 'a') as output_file:
            output_file.write(json.dumps(hash_data_dict, indent=4, sort_keys=False) + "\n")

# print and write to file the current hash count stats
    hash_counters['total samples'] = index
    print('\nCurrent hash count stats:\n')
    print(json.dumps(hash_counters, indent=4, sort_keys=False) + '\n')
    with open('threatname_data_stats.json', 'w') as hash_file:
        hash_file.write(json.dumps(hash_counters, indent=4, sort_keys=False) + "\n")


def main():

    """hash_data main module"""

# Map starting index to 1 if a new run or one more than the last value as a continuing run
# Init hash counters to zero

    index = 1
    hash_counters = init_hash_counters()

# read hash list from file
    threatname_list = get_threatname_list(threatnamefile)

# iterate through the hash list getting sample and signature data

    for threatname in threatname_list:

        sample_data = {}
        hash_data_dict = {}

# Used for Elasticsearch bulk import
# Formatting requires index data per document record
        index_tag_full = elk_index(index_name, index)

# query Autofocus to get sample and signature coverage data
        sample_data = get_sample_data(hostname, api_key, threatname, hash_counters)

        if sample_data['verdict'] != 'No sample found':
            hash_data_dict, hash_counters = \
                get_sig_coverage(hostname, api_key, sample_data, hash_counters)

# write output to file - per hash cycle to view updates during runtime
        write_to_file(index, index_tag_full, hash_data_dict, hash_counters)

        index += 1


if __name__ == '__main__':
    main()
