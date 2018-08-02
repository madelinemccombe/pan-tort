####!/usr/bin/env python3
"""
hash_data reads a list of md5 hash strings and performs 2 Autofocus api
queries to get verdict/filetype and then signature coverage data
This provides contextual information in test environments beyond just a hash miss
"""
import sys
import json
import time
import requests

from datetime import datetime
from af_api import api_key
from conf import hostname, hashfile, hashtype, elk_index_name, get_sig_data, af_query, querytype
from filetypedata import filetypetags

# FIXME doesn't check for not-found sample hashes - key for the hashlist load
# FIXME broke the MD5/SHA1 option - only does sha256 at the moment
# FIXME better view of sig coverage data to simplify views


def init_hash_counters():

    """
    initialize hash counters
    :return: send back hash counters = zero
    """

    hash_counters = {}
    hash_count_values = ['total samples', 'malware', 'mal_inactive_sig', 'mal_active_sig',
                         'mal_no_sig', 'grayware', 'benign', 'phishing', 'No sample found']

    for value in hash_count_values:
        hash_counters[value] = 0

    return hash_counters


def elk_index():

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


def get_hash_list():

    """
    read in the list of hashes from a text file
    :param filename: name of the hashfile
    :return: return list of hash values
    """

    with open(hashfile, 'r') as hash_file:
        hash_list = hash_file.read().splitlines()

    return hash_list


def multi_query(hashlist):

    """
    initial query into autofocus for a specific hash value
    :param hashvalue: hash for the search
    :return: autofocus response from initial query
    """

    if querytype == 'hash':
        query = {"operator": "all",
                 "children": [{"field":"sample.sha256", "operator":"is in the list", "value":hashlist}]}

    elif querytype == 'autofocus':
        query = af_query


    print('Initiating query to Autofocus')
    search_values = {"apiKey": api_key,
                     "query": query,
                     "size": 4000,
                     "scope": "public",
                     "type": "scan",
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


def get_query_results(search_dict, startTime, query_tag):

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

                parse_sample_data(autofocus_results, startTime, index, query_tag)
                index += 1

                print(f'Results update for page {index}:\n')
                print(f"samples found so far: {autofocus_results['total']}")
                print(f"Search percent complete: {autofocus_results['af_complete_percentage']}%")
                print(f"samples processed in this batch: {len(autofocus_results['hits'])}")
                totalsamples = sum(running_length)
                print(f'total samples processed: {totalsamples}\n')
                minute_pts_rem = autofocus_results['bucket_info']['minute_points_remaining']
                daily_pts_rem = autofocus_results['bucket_info']['daily_points_remaining']
                print(f'AF quota update: {minute_pts_rem} minute points and {daily_pts_rem} daily points remaining')
                elapsedtime = datetime.now() - startTime
                print(f'Elasped run time is {elapsedtime}')
                print('=' * 80)


            if autofocus_results['af_in_progress'] is False :
                search_progress = 'FIN'
        else:
            print('Autofocus still queuing up the search...')

    print('\n')
    print('=' * 80)
    print('\n')
    print('sample processing complete')
    print(f"total hits: {autofocus_results['total']}")
    totalsamples = sum(running_length)
    print(f'total samples processed: {totalsamples}')

    return autofocus_results


def parse_sample_data(autofocus_results, startTime, index, query_tag):

    """
    primary function to do both the init query and keep checking until search complete
    :param hashvalue: sample hash value
    :param hash_counters: updating running stats counters
    :return: update dictionary with sample data
    """

    malware_values = {'0': 'benign', '1': 'malware', '2': 'grayware', '3': 'phishing'}

    index_tag_full = elk_index()

    with open('tagdata.json', 'r') as tag_file:
        tag_dict = json.load(tag_file)

    listsize = len(autofocus_results['hits'])

    for listpos in range(0, listsize):
        sha256hash = autofocus_results['hits'][listpos]['_source']['sha256']
        hash_data_dict = {}
        hash_num = listpos + 1

    # AFoutput is json output converted to python dictionary
        hash_data_dict['hashvalue'] = sha256hash

    # initial AF query to get sample data include sha256 hash and WF verdict

        verdict_num = autofocus_results['hits'][listpos]['_source']['malware']
        verdict_text = malware_values[str(verdict_num)]
        hash_data_dict['verdict'] = verdict_text
        filetype = autofocus_results['hits'][listpos]['_source']['filetype']
        hash_data_dict['filetype'] = filetype
        hash_data_dict['filetype_group'] = filetypetags[filetype]
        hash_data_dict['sha256hash'] = autofocus_results['hits'][listpos]['_source']['sha256']
        hash_data_dict['create_date'] = autofocus_results['hits'][listpos]['_source']['create_date']
        hash_data_dict['query_tag'] = query_tag
        hash_data_dict['query_time'] = str(startTime)

        if 'tag' in autofocus_results['hits'][listpos]['_source']:

            hash_data_dict['all_tags'] = autofocus_results['hits'][listpos]['_source']['tag']

            priority_tags_public = []
            priority_tags_name = []

            for tag in hash_data_dict['all_tags']:

                if 'tag_class' in tag_dict['_tags'][tag]:

                    tag_class = tag_dict['_tags'][tag]['tag_class']
                    tag_name = tag_dict['_tags'][tag]['tag_name']
                    if tag_class == 'malware_family' or tag_class == 'campaign' or tag_class == 'actor':
                        priority_tags_public.append(tag)
                        priority_tags_name.append(tag_name)

                    hash_data_dict['priority_tags_public'] = priority_tags_public
                    hash_data_dict['priority_tags_name'] = priority_tags_name

                if 'tag_groups' in tag_dict['_tags'][tag]:
                    taggroups = []
                    for group in tag_dict['_tags'][tag]['tag_groups']:
                        taggroups.append(group['tag_group_name'])

                    hash_data_dict['tag_groups'] = taggroups

        if get_sig_data == 'yes':
            print(f"\ngetting sig coverage for {hash_num} of {listsize}: {sha256hash}")

            search_values = {"apiKey": api_key,
                             "coverage": 'true',
                             "sections": ["coverage"],
                             }

            headers = {"Content-Type": "application/json"}
            search_url = f'https://{hostname}/api/v1.0/sample/{sha256hash}/analysis'

            try:
                search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
                search.raise_for_status()
            except requests.exceptions.HTTPError:
                print(search)
                print(search.text)
                print('\nCorrect errors and rerun the application\n')
                sys.exit()

            results_analysis = json.loads(search.text)
            hash_data_dict['dns_sig'] = results_analysis['coverage']['dns_sig']
            hash_data_dict['wf_av_sig'] = results_analysis['coverage']['wf_av_sig']
            hash_data_dict['fileurl_sig'] = results_analysis['coverage']['fileurl_sig']

            print('Sig coverage search complete')
            minute_pts_rem = results_analysis['bucket_info']['minute_points_remaining']
            daily_pts_rem = results_analysis['bucket_info']['daily_points_remaining']
            print(f'AF quota update:  {minute_pts_rem} minute points and {daily_pts_rem} daily points remaining')
            elapsedtime = datetime.now() - startTime
            print(f'Elasped run time is {elapsedtime}')


        # Write dict contents to running file both estack and pretty json versions
        if index == 1 and listpos == 0:
            with open('hash_data_estack.json', 'w') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

            with open('hash_data_pretty.json', 'w') as hash_file:
                hash_file.write(json.dumps(hash_data_dict, indent=4, sort_keys=False) + "\n")

        else:
            with open('hash_data_estack.json', 'a') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

            with open('hash_data_pretty.json', 'a') as hash_file:
                hash_file.write(json.dumps(hash_data_dict, indent=4, sort_keys=False) + "\n")

    return


def main():

    """hash_data main module"""
    hash_list = []


    if querytype == 'hash':
        # supported hashtypes are: md5, sha1, sha256
        if hashtype != 'md5' and hashtype != 'sha1' and hashtype != 'sha256':
            print('\nOnly hash types md5, sha1, or sha256 are supported')
            print('correct in af_api.py and try again')
            sys.exit(1)

        # read hash list from file
        hash_list = get_hash_list()

    query_tag = input('Enter brief tag name for this data: ')

    startTime = datetime.now()


    #submit bulk query for sample data to AF
    searchrequest = multi_query(hash_list)

    #get query results and parse output
    get_query_results(searchrequest, startTime, query_tag)


if __name__ == '__main__':
    main()
