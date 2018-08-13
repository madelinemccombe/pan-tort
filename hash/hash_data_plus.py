# Copyright (c) 2018, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Scott Shoaf <sshoaf@paloaltonetworks.com>

'''
Palo Alto Networks hash_data_plus.py

Reads in a list of samples hashes with output of malware verdict, file types, malware family,
and signature coverage data.

Outputs are formatted for both bulk load into Elasticsearch and readable 'pretty format' json
Outputs are stored in the out_estack and out_pretty directories

Initial step to use is to have the af_api.py populated with the Autofocus API key value
Then populate the hash_list and run the script

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import sys
import json
import time
import requests
from datetime import datetime

import conf
from af_api import api_key
from filetypedata import filetypetags


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
    :param conf.elk_index_name: name of data index in elasticsearch
    :return: index tag to write as line in the output json file
    """

    index_tag_full = {}
    index_tag_inner = {}
    index_tag_inner['_index'] = conf.elk_index_name
    index_tag_inner['_type'] = conf.elk_index_name
    index_tag_full['index'] = index_tag_inner

    return index_tag_full


def get_search_list():

    """
    read in the list of elements from a text file
    :param filename: name of the search list file
    :return: return list of search values
    """

    with open(conf.inputfile, 'r') as search_file:
        search_list = search_file.read().splitlines()

    return search_list


def is_active(dict, searchFor):
    for k in dict:
        for v in dict[k]:
            if searchFor in v:
                return 'Active'
    return 'Inactive'


def multi_query(searchlist):

    """
    initial query into autofocus for a specific hash value
    :param searchlist: set of hash values up to 1000 entries used in a single search
    :return: autofocus response from initial query
    """

    print('Initiating query to Autofocus')

    fieldvalue = f'sample.{conf.hashtype}'
    query = {"operator": "all",
             "children": [{f"field":fieldvalue, "operator":"is in the list", "value":searchlist}]}

    # this used a scan type query to scale up beyond 4000 reponses from Autofocus
    search_values = {"apiKey": api_key,
                     "query": query,
                     "size": 4000,
                     "scope": "public",
                     "type": "scan",
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


def scantype_query_results(search_dict, startTime, query_tag, search):

    """
    keep checking autofocus until a hit or search complete
    :param search_dict: initial response including the cookie value
    :param startTime: when the script started - used to track run time
    :param query_tag: identifier for this script run used as estack tag
    :param search: for multi-page search to denote which 1000 block being used
    :return: autofocus search results dictionary or null if no hits
    """

    autofocus_results = {}

    cookie = search_dict['af_cookie']
    print(f'Tracking cookie is {cookie}')
    print('Getting sample data...\n')

    search_progress = 'start'
    index = 1

    # looping across 1000 element input lists requires a file read if > 1 loops
    if search == 1:
        all_sample_dict = {}
        all_sample_dict['samples'] = []
    else:
        with open(f'out_pretty/hash_data_pretty_{query_tag}_nosigs.json', 'r') as hash_file:
            all_sample_dict = json.load(hash_file)

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

            if autofocus_results['total'] != 0:
                # parse data and output estack json elements
                # return is running dict of all samples for pretty json output
                all_sample_dict = parse_sample_data(autofocus_results, startTime, index, query_tag, all_sample_dict, search)
                with open(f'out_pretty/hash_data_pretty_{query_tag}_nosigs.json', 'w') as hash_file:
                    hash_file.write(json.dumps(all_sample_dict, indent=2, sort_keys=False) + "\n")
                index += 1

                print(f'Results update for page {index}: {query_tag}\n')
                print(f"samples found so far: {autofocus_results['total']}")
                print(f"Search percent complete: {autofocus_results['af_complete_percentage']}%")
                print(f"samples processed in this batch: {len(autofocus_results['hits'])}")
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
    print(f'sample processing complete for {query_tag}')
    print(f"total hits: {autofocus_results['total']}")
    totalsamples = sum(running_length)
    print(f'total samples processed: {totalsamples}')

    return autofocus_results


def parse_sample_data(autofocus_results, startTime, index, query_tag, hash_data_dict_pretty, search):

    """
    parse the AF reponse and augment the data with file type, tag, malware information
    :param autofocus_results: array of data from AF multi-query response
    :param startTime: time script started; used to track run time
    :param index: note which cycle through the search block; if > 1 does file appends to existing file
    :param query_tag: identifier for this script run used as estack tag
    :param search: for multi-page search to denote which 1000 block being used
    :param hash_data_dict_pretty: master dict appended with each cycle and eventully output as pretty json file
    :return: update dictionary with sample data
    """

    # mapping of tag # to text name
    malware_values = {'0': 'benign', '1': 'malware', '2': 'grayware', '3': 'phishing'}

    index_tag_full = elk_index()

    # used to have a full view of AF tag data for data augmentation
    # for a current list, should run gettagdata.py periodically
    with open('tagdata.json', 'r') as tag_file:
        tag_dict = json.load(tag_file)

    listsize = len(autofocus_results['hits'])

    # interate through AF results to create dict key/values for each sample hash
    for listpos in range(0, listsize):
        keyhash = autofocus_results['hits'][listpos]['_source'][conf.hashtype]
        hash_data_dict = {}

        # AFoutput is json output converted to python dictionary
        hash_data_dict['hashvalue'] = keyhash

        hash_data_dict['sha256hash'] = autofocus_results['hits'][listpos]['_source']['sha256']
        hash_data_dict['create_date'] = autofocus_results['hits'][listpos]['_source']['create_date']
        hash_data_dict['query_tag'] = query_tag
        hash_data_dict['query_time'] = str(startTime)

        # initial AF query to get sample data include sha256 hash and WF verdict
        # sha256 is required for sig queries; does not support md5 or sha1
        verdict_num = autofocus_results['hits'][listpos]['_source']['malware']
        verdict_text = malware_values[str(verdict_num)]
        hash_data_dict['verdict'] = verdict_text

        filetype = autofocus_results['hits'][listpos]['_source']['filetype']
        hash_data_dict['filetype'] = filetype
        hash_data_dict['filetype_group'] = filetypetags[filetype]

        # not all samples have a tag value; uses when a tag value is present
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

        # this creates a json format with first record as samples then appended json list entries
        # proper json format to read the file in during run to append with new data
        hash_data_dict_pretty['samples'].append(hash_data_dict)

        # Write dict contents to running file both estack and pretty json versions
        if index == 1 and listpos == 0 and search == 1:
            with open(f'out_estack/hash_data_estack_{query_tag}_nosigs.json', 'w') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")
        else:
            with open(f'out_estack/hash_data_estack_{query_tag}_nosigs.json', 'a') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

    return hash_data_dict_pretty


def get_sig_data(query_tag, startTime):

    with open(f'out_pretty/hash_data_pretty_{query_tag}_nosigs.json', 'r') as samplesfile:
        samples_dict = json.load(samplesfile)

    index_tag_full = elk_index()
    index = 1

    listsize = len(samples_dict['samples'])


    for listpos in range(0, listsize):

        hash_data_dict_pretty = {}
        hash_data_dict_pretty['samples'] = []
        hash_data_dict = samples_dict['samples'][listpos]
        sha256hash = hash_data_dict['sha256hash']
        hash_num = listpos + 1

        print(f"\ngetting sig coverage for {hash_num} of {listsize}: {query_tag}")
        print(f'hash: {sha256hash}')

        search_values = {"apiKey": api_key,
                         "coverage": 'true',
                         "sections": ["coverage"],
                         }

        headers = {"Content-Type": "application/json"}
        search_url = f'https://{conf.hostname}/api/v1.0/sample/{sha256hash}/analysis'

        try:
            search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
            search.raise_for_status()
        except requests.exceptions.HTTPError:
            print(search)
            print(search.text)
            print('\nCorrect errors and rerun the application\n')
            sys.exit()

        results_analysis = json.loads(search.text)

        sigtypes = ['dns_sig', 'wf_av_sig', 'fileurl_sig']

        for type in sigtypes:
            # add the full response to the doc
            hash_data_dict[type] = results_analysis['coverage'][type]

            # check sig state by type and add to doc
            sig_state = f'{type}_sig_state'
            # convert to string for quick text search
            sigstring = json.dumps(results_analysis['coverage'][type])
            if sigstring.find('true') != -1:
                hash_data_dict[sig_state] = 'active'
            elif sigstring.find('true') == -1 and sigstring.find('false') != -1:
                hash_data_dict[sig_state] = 'inactive'
            else:
                hash_data_dict[sig_state] = 'none'

        # set doc value for any sig coverage as active, inactive, none
        if search.text.find('true') != -1:
            hash_data_dict['sig_state_all'] = 'active'
        elif search.text.find('true') == -1 and search.text.find('false') != -1:
            hash_data_dict['sig_state_all'] = 'inactive'
        else:
            hash_data_dict['sig_state_all'] = 'none'

        print('Sig coverage search complete')
        minute_pts_rem = results_analysis['bucket_info']['minute_points_remaining']
        daily_pts_rem = results_analysis['bucket_info']['daily_points_remaining']
        print(f'AF quota update:  {minute_pts_rem} minute points and {daily_pts_rem} daily points remaining')
        elapsedtime = datetime.now() - startTime
        print(f'Elasped run time is {elapsedtime}')

        hash_data_dict_pretty['samples'].append(hash_data_dict)

        # Write dict contents to running file both estack and pretty json versions
        if index == 1 and listpos == 0:
            with open(f'out_estack/hash_data_estack_{query_tag}_sigs.json', 'w') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

            with open(f'out_pretty/hash_data_pretty_{query_tag}_sigs.json', 'w') as hash_file:
                hash_file.write(json.dumps(hash_data_dict_pretty, indent=4, sort_keys=False) + "\n")
        else:
            with open(f'out_estack/hash_data_estack_{query_tag}_sigs.json', 'a') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

            with open(f'out_pretty/hash_data_pretty_{query_tag}_sigs.json', 'a') as hash_file:
                hash_file.write(json.dumps(hash_data_dict_pretty, indent=4, sort_keys=False) + "\n")

        index += 1

    return

def main():

    """search_data main module"""

    # for longer lists may have to break list in 1000 size pieces
    # for autofocus type queries on do a single search

    query_tag = input('Enter brief tag name for this data: ')
    startTime = datetime.now()
    listend = -1


    # supported conf.hashtypes are: md5, sha1, sha256
    if conf.hashtype != 'md5' and conf.hashtype != 'sha1' and conf.hashtype != 'sha256':
        print('\nOnly hash types md5, sha1, or sha256 are supported')
        print('correct in af_api.py and try again')
        sys.exit(1)


    # read items list from file
    search_list_all = get_search_list()
    listlength = len(search_list_all)
    numsearches = int(listlength / 1000) + 1

    for search in range(1, numsearches + 1):
    #submit bulk query for sample data to AF

        print(f'\nworking with search interval {search} of {numsearches}')
        liststart = listend + 1
        listend += 1000

        search_list = search_list_all[liststart:listend]
        print(f'query is sending {len(search_list)} items as search elements')

        searchrequest = multi_query(search_list)

        #get query results and parse output
        scantype_query_results(searchrequest, startTime, query_tag, search)

    if conf.getsigdata == 'yes':
            get_sig_data(query_tag, startTime)


if __name__ == '__main__':
    main()
