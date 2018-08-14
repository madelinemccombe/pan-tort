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

Reads in a list of samples hashes with output of malware verdict, file types,
malware family, and signature coverage data.

Outputs are formatted for both bulk load into Elasticsearch and
readable 'pretty format' json

Outputs are stored in the out_estack and out_pretty directories

Before first use, create af_api.py with the Autofocus API key value
Then populate the hash_list and run the script

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import sys
import os
import json
import time
from datetime import datetime
import requests

# local imports for static input data
import conf
from af_api import api_key
from filetypedata import filetypetags


def init_hash_counters():

    '''
    initialize hash counters
    :return: send back hash counters = zero
    '''

    hash_counters = {}
    hash_count_values = ['total samples', 'malware', 'mal_inactive_sig',
                         'mal_active_sig', 'mal_no_sig', 'grayware', 'benign',
                         'phishing', 'No sample found']

    for value in hash_count_values:
        hash_counters[value] = 0

    return hash_counters


def elk_index():

    '''
    set up elasticsearch bulk load index
    :param conf.elk_index_name: name of data index in elasticsearch
    :return: index tag to write as line in the output json file
    '''

    index_tag_full = {}
    index_tag_inner = {}
    index_tag_inner['_index'] = conf.elk_index_name
    index_tag_inner['_type'] = conf.elk_index_name
    index_tag_full['index'] = index_tag_inner

    return index_tag_full


def output_dir(dir_name):

    '''
    check for the output dirs and if exist=False then create them
    :param dir_name: directory name to be check and possibly created
    '''

    # check if the out_estack dir exists and if not then create it
    if os.path.isdir(dir_name) is False:
        os.mkdir(dir_name, mode=0o755)


def get_search_list():

    '''
    read in the list of elements from a text file
    :param filename: name of the search list file
    :return: return list of search values
    '''

    with open(conf.inputfile, 'r') as search_file:
        search_list = search_file.read().splitlines()

    return search_list


def is_active(sigdict, searchfor):

    '''
    check to see if sig is active/inactive based on AF response
    any true sets the return to Active
    :param dict: dict loaded from json response per sig type
    :param searchfor: value to search for in the sig reponse dict
    :return:
    '''
    for sigkey in sigdict:
        for sigentry in sigdict[sigkey]:
            if searchfor in sigentry:
                return 'Active'
    return 'Inactive'


def multi_query(searchlist):

    '''
    initial query into autofocus for a specific hash value
    :param searchlist: set of hash values used in a single search (max 1000)
    :return: autofocus response from initial query
    '''

    print('Initiating query to Autofocus')

    fieldvalue = f'sample.{conf.hashtype}'
    query = {"operator": "all",
             "children": [{f"field":fieldvalue, "operator":"is in the list",
                           "value":searchlist}]}

    # uses a type=scan query to scale beyond 4000 samples hits from Autofocus
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
        search = requests.post(search_url, headers=headers,
                               data=json.dumps(search_values))
        print('Search query posted to Autofocus')
        search.raise_for_status()
    except requests.exceptions.HTTPError:
        print(search)
        print(search.text)
        print('\nCorrect errors and rerun the application\n')
        sys.exit()

    search_dict = json.loads(search.text)

    return search_dict


def scantype_query_results(search_dict, start_time, query_tag, search):

    '''
    With type=scan each results post with the same cookie will return
    current set of hits
    This creates an extensible model for larger response sets > 4000
    Responses are returned in pages of 1000 entries
    Checks continue until search is complete and all pages of data returned
    :param search_dict: initial response including the cookie value
    :param start_time: when the script started - used to track run time
    :param query_tag: identifier for this script run used as estack tag
    :param search: for multi-page search to denote which 1000 block being used
    :return: autofocus search results dictionary or null if no hits
    '''

    autofocus_results = {}

    cookie = search_dict['af_cookie']
    print(f'Tracking cookie is {cookie}')
    print('Getting sample data...\n')

    search_progress = 'start'
    index = 1

    running_total = []
    running_length = []

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
            results_url = f'https://{conf.hostname}/api/v1.0/samples/results/{cookie}'
            headers = {"Content-Type": "application/json"}
            results_values = {"apiKey": api_key}
            results = requests.post(results_url, headers=headers,
                                    data=json.dumps(results_values))
            results.raise_for_status()
        except requests.exceptions.HTTPError:
            print(results)
            print(results.text)
            print('\nCorrect errors and rerun the application\n')
            sys.exit()

        autofocus_results = results.json()

        running_total.append(autofocus_results['total'])
        running_length.append(len(autofocus_results['hits']))

        if 'total' in autofocus_results:

            if autofocus_results['total'] != 0:
                # parse data and output estack json elements
                # return is running dict of all samples for pretty json output
                all_sample_dict = parse_sample_data(autofocus_results,
                                                    start_time, index, query_tag,
                                                    all_sample_dict, search)
                with open(f'{conf.out_pretty}/hash_data_pretty_{query_tag}_nosigs.json', 'w')as hash_file:
                    hash_file.write(json.dumps(all_sample_dict, indent=2, sort_keys=False) + "\n")
                index += 1

                print(f'Results update for page {index}: {query_tag}\n')
                print(f"samples found so far: {autofocus_results['total']}")
                print(f"Search percent complete: {autofocus_results['af_complete_percentage']}%")
                print(f"samples processed in this batch: {len(autofocus_results['hits'])}")
                totalsamples = sum(running_length)
                print(f'total samples processed: {totalsamples}\n')
                minute_pts_rem = autofocus_results['bucket_info']['minute_points_remaining']
                daily_pts_rem = autofocus_results['bucket_info']['daily_points_remaining']
                print(f'AF quota update: {minute_pts_rem} minute points and {daily_pts_rem} daily points remaining')
                elapsedtime = datetime.now() - start_time
                print(f'Elasped run time is {elapsedtime}')
                print('=' * 80)

            if autofocus_results['af_in_progress'] is False:
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


def parse_sample_data(autofocus_results, start_time, index, query_tag, hash_data_dict_pretty, search):

    '''
    parse the AF reponse and augment the data with file type, tag, malware
    then write 2 files: pretty json and estack for bulk load into elasticsearch
    :param autofocus_results: array of data from AF multi-query response
    :param start_time: time script started; used to track run time
    :param index: note which cycle through the search block for file w or a
    :param query_tag: identifier for this script run used as estack tag
    :param search: for multi-page search to denote which 1000 block being used
    :param hash_data_dict_pretty: master set of data to write out to json
    :return: update dictionary with sample data
    '''

    # mapping of tag # to text name
    malware_values = {'0': 'benign', '1': 'malware',
                      '2': 'grayware', '3': 'phishing'}

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
        hash_data_dict['sample_found'] = True

        hash_data_dict['sha256hash'] =\
            autofocus_results['hits'][listpos]['_source']['sha256']
        hash_data_dict['create_date'] =\
            autofocus_results['hits'][listpos]['_source']['create_date']
        hash_data_dict['query_tag'] = query_tag
        hash_data_dict['query_time'] = str(start_time)

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

            hash_data_dict['all_tags'] =\
                autofocus_results['hits'][listpos]['_source']['tag']

            priority_tags_public = []
            priority_tags_name = []

            for tag in hash_data_dict['all_tags']:

                if 'tag_class' in tag_dict['_tags'][tag]:

                    tag_class = tag_dict['_tags'][tag]['tag_class']
                    tag_name = tag_dict['_tags'][tag]['tag_name']
                    if tag_class in ('malware_family', 'campaign', 'actor'):
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
            with open(f'{conf.out_estack}/hash_data_estack_{query_tag}_nosigs.json', 'w') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")
        else:
            with open(f'{conf.out_estack}/hash_data_estack_{query_tag}_nosigs.json', 'a') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

    return hash_data_dict_pretty


def missing_samples(query_tag, start_time):
    '''
    once the query is complete and samples found have to look for misses
    this reads in the pretty json file to get the found list
    then appends the estack and pretty nosigs files with hash misses
    :return:
    '''

    index_tag_full = elk_index()

    # initialize tracking dict for samples not found
    samples_notfound_dict = {}
    hash_list = get_search_list()

    # read in the full set of samples after query is complete
    with open(f'{conf.out_pretty}/hash_data_pretty_{query_tag}_nosigs.json', 'r') as samplesfile:
        samples_dict = json.load(samplesfile)

    found_list = []
    for sample in samples_dict['samples']:
        found_list.append(sample['hashvalue'])

    for sample in hash_list:
        if sample in found_list:
            pass
        else:
            samples_notfound_dict['hashvalue'] = sample
            samples_notfound_dict['sample_found'] = False
            samples_notfound_dict['query_tag'] = query_tag
            samples_notfound_dict['query_time'] = str(start_time)
            samples_notfound_dict['create_date'] = str(start_time)

            # Write dict contents to running file both estack and pretty json versions
            with open(f'{conf.out_estack}/hash_data_estack_{query_tag}_nosigs.json', 'a') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(samples_notfound_dict, indent=None, sort_keys=False) + "\n")

            samples_dict['samples'].append(samples_notfound_dict)

    with open(f'{conf.out_pretty}/hash_data_pretty_{query_tag}_nosigs.json', 'w') as hash_file:
        hash_file.write(json.dumps(samples_dict, indent=4, sort_keys=False) + "\n")


def get_sig_data(query_tag, start_time):

    '''
    after the initial sample data is captured then check for sig coverage
    only works with SHA256 so MD5/SHA1 input has SHA256 added from AF
    only a single hash queried at a time since hash value in the url request
    a new file appended with sigs added to the archive
    :param query_tag: query descriptive tag used in elasticsearch as a filter
    :param start_time: start time of the script to capture run time
    :return:
    '''

    # stage 1 is the sample query and data capture stored as file nosigs
    # that output is read in to a dict, updated, and output as sigs file
    with open(f'{conf.out_pretty}/hash_data_pretty_{query_tag}_nosigs.json', 'r') as samplesfile:
        samples_dict = json.load(samplesfile)

    index_tag_full = elk_index()
    index = 1

    listsize = len(samples_dict['samples'])

    hash_data_dict_pretty = {}
    hash_data_dict_pretty['samples'] = []

    for listpos in range(0, listsize):

        hash_data_dict = samples_dict['samples'][listpos]
        hash_num = listpos + 1

        if samples_dict['samples'][listpos]['sample_found'] is True:

            sha256hash = hash_data_dict['sha256hash']

            print(f"\ngetting sig coverage for {hash_num} of {listsize}: {query_tag}")
            print(f'hash: {sha256hash}')

            # script only returns coverage info: sections:coverage flag
            # the attribute coverage=true also required to return coverage data
            search_values = {"apiKey": api_key,
                             "coverage": 'true',
                             "sections": ["coverage"],
                             }

            headers = {"Content-Type": "application/json"}
            search_url = f'https://{conf.hostname}/api/v1.0/sample/{sha256hash}/analysis'

            try:
                search = requests.post(search_url, headers=headers,
                                       data=json.dumps(search_values))
                search.raise_for_status()
            except requests.exceptions.HTTPError:
                print(search)
                print(search.text)
                print('\nCorrect errors and rerun the application\n')
                sys.exit()

            # this is a single request-response interaction
            # no cookie and updated checks required
            results_analysis = json.loads(search.text)

            # sig types with coverage data to be captured
            sigtypes = ['dns_sig', 'wf_av_sig', 'fileurl_sig']

            for stype in sigtypes:
                # add the full response to the doc
                hash_data_dict[stype] = results_analysis['coverage'][stype]

                # check sig state by type and add to doc
                sig_state = f'{stype}_sig_state'
                # convert to string for quick text search
                sigstring = json.dumps(results_analysis['coverage'][stype])
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
            minute_pts_rem =\
                results_analysis['bucket_info']['minute_points_remaining']
            daily_pts_rem =\
                results_analysis['bucket_info']['daily_points_remaining']
            print(f'AF quota update:  {minute_pts_rem} minute points and {daily_pts_rem} daily points remaining')
            elapsedtime = datetime.now() - start_time
            print(f'Elasped run time is {elapsedtime}')

        hash_data_dict_pretty['samples'].append(hash_data_dict)

        # Write dict contents to running file both estack and pretty json versions
        if index == 1 and listpos == 0:
            with open(f'{conf.out_estack}/hash_data_estack_{query_tag}_sigs.json', 'w') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

            with open(f'{conf.out_pretty}/hash_data_pretty_{query_tag}_sigs.json', 'w') as hash_file:
                hash_file.write(json.dumps(hash_data_dict_pretty, indent=4, sort_keys=False) + "\n")
        else:
            with open(f'{conf.out_estack}/hash_data_estack_{query_tag}_sigs.json', 'a') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(hash_data_dict, indent=None, sort_keys=False) + "\n")

        index += 1


    with open(f'{conf.out_pretty}/hash_data_pretty_{query_tag}_sigs.json', 'w') as hash_file:
                    hash_file.write(json.dumps(hash_data_dict_pretty, indent=4, sort_keys=False) + "\n")


def main():

    '''search_data main module'''

    # for longer lists may have to break list in 1000 size pieces
    # for autofocus type queries on do a single search

    query_tag = input('Enter brief tag name for this data: ')
    start_time = datetime.now()
    listend = -1
    ok_to_get_sigs = True


    # supported conf.hashtypes are: md5, sha1, sha256
    if conf.hashtype != 'md5' and conf.hashtype != 'sha1' and conf.hashtype != 'sha256':
        print('\nOnly hash types md5, sha1, or sha256 are supported')
        print('correct in af_api.py and try again')
        sys.exit(1)

    # check for output dirs and created if needed
    output_dir(conf.out_estack)
    output_dir(conf.out_pretty)

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
        scantype_query_results(searchrequest, start_time, query_tag, search)

    # check that the output sigs file exists if AF hits 1= 0
    # if no file, check that hashtype in conf.py matches hashlist.txt type
    try:
        with open(f'{conf.out_pretty}/hash_data_pretty_{query_tag}_nosigs.json', 'r'):
            pass
    except IOError as nofile_error:
        print(nofile_error)
        print(f'Unable to open out_pretty/hash_data_pretty_{query_tag}_nosigs.json')
        print('This file is output from the initial sample search and read in to create a sig coverage output')
        print('If hits are expected check that the hashtype in conf.py matches the hashes in hash_list.txt')
        ok_to_get_sigs = False

    # find AF sample misses and add to the estack json file as not found
    missing_samples(query_tag, start_time)

    if conf.getsigdata == 'yes' and ok_to_get_sigs is True:
        get_sig_data(query_tag, start_time)


if __name__ == '__main__':
    main()
