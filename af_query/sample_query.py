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
Palo Alto Networks threat_data.py

Reads in a list of samples hashes, threatnames, or af_query as json

Output of malware verdict, file types,
malware family, and optionally signature coverage data.

Outputs are formatted for both bulk load into Elasticsearch and
readable 'pretty format' json

Outputs are stored in the out_estack and out_pretty directories

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import argparse
import sys
import os
import json
import time
import csv
from datetime import datetime
import requests

# adding shared dir for imports
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(here, '../shared')))

# script to create or update the tagdata.json list from Autofocus
from gettagdata import tag_query

# local imports for static data input
import conf
from filetypedata import filetypetags


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

def clean_exploit_data():

    '''
    read csv vulnerability object file and create dict with CVE key
    :return: return cve dict
    '''

    # create cve_dict based on parse of vulnerability csv file
    cve_dict = {}

    # read in vulnerability csv file and parse
    # some CVE fields are also comma separated
    with open(f'data/{conf.inputfile_exploits}', newline='') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            # skip blank CVE records
            if row['CVE']:
                # break out multi-cve field so single cve value in dict
                if ',' in row['CVE']:
                    cve_many = row['CVE'].split(',')
                    for cve in cve_many:
                        cve_dict[cve] = {}
                        cve_dict[cve]['Threat Name'] = row['Threat Name']
                        cve_dict[cve]['Category'] = row['Category']
                        cve_dict[cve]['Severity'] = row['Severity']

                else:
                    cve_dict[row['CVE']] = {}
                    cve_dict[row['CVE']]['Threat Name'] = row['Threat Name']
                    cve_dict[row['CVE']]['Category'] = row['Category']
                    cve_dict[row['CVE']]['Severity'] = row['Severity']

    return cve_dict


def create_cve_list():

    '''
    read in autofocus cve tag data and get list of cve values
    :return: return list of cve values
    '''

    # create cve tags list based on parse of autofocus tag data
    cve_tag_list = []

    # for a current list, should run gettagdata.py periodically
    with open('data/tagdata.json', 'r') as tag_file:
        tag_dict = json.load(tag_file)

        for tag in tag_dict['_tags']:
            if 'CVE' in tag:
                if '_' not in tag:
                    cve_tag_list.append(tag_dict['_tags'][tag]['public_tag_name'])

    return cve_tag_list

def get_search_list():

    '''
    read in the list of elements from a text file
    :param filename: name of the search list file
    :return: return list of search values
    '''

    with open(conf.inputfile, 'r') as search_file:
        search_list = search_file.read().splitlines()

    return search_list


def multi_query(searchlist, api_key):

    '''
    initial query into autofocus for a specific hash value
    :param hashvalue: hash for the search
    :return: autofocus response from initial query
    '''

    print('Initiating query to Autofocus')


    if conf.querytype == 'hash':
        fieldvalue = f'sample.{conf.hashtype}'
        query = {"operator": "all",
                 "children": [{f"field":fieldvalue, "operator":"is in the list", "value":searchlist}]}

    if conf.querytype == 'threat':
        query = {"operator": "all",
                 "children": [
                    {"field": "sample.create_date", "operator": "is after", "value": ["2018-06-01T00:00:00", "2018-08-08T23:59:59"]},
                    {"field": "sample.threat_name", "operator": "is in the list", "value": searchlist}]}

    if conf.querytype == 'autofocus':
        query = conf.af_query

    print(query)


    search_values = {"apiKey": api_key,
                     "query": query,
                     "size": 4000,
                     "scope": "global",
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


def scantype_query_results(search_dict, start_time, query_tag, search, api_key, exploits):

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
        with open(f'{conf.out_pretty}/hash_data_pretty_{query_tag}_nosigs.json', 'r') as hash_file:
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

            running_total.append(autofocus_results['total'])
            running_length.append(len(autofocus_results['hits']))

            if autofocus_results['total'] != 0:
                # parse data and output estack json elements
                # return is running dict of all samples for pretty json output
                all_sample_dict = parse_sample_data(autofocus_results, start_time, index, query_tag, all_sample_dict, search, exploits)
                with open(f'{conf.out_pretty}/hash_data_pretty_{query_tag}_nosigs.json', 'w') as hash_file:
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


            if autofocus_results['af_in_progress'] is False :
                search_progress = 'FIN'
        else:
            print('Autofocus still queuing up the search...')
            time.sleep(5)

    print('\n')
    print('=' * 80)
    print('\n')
    print(f'sample processing complete for {query_tag}')
    print(f"total hits: {autofocus_results['total']}")
    totalsamples = sum(running_length)
    print(f'total samples processed: {totalsamples}')

    return autofocus_results


def parse_sample_data(autofocus_results, start_time, index, query_tag, hash_data_dict_pretty, search, exploits):

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
    malware_values = {'0': 'benign', '1': 'malware', '2': 'grayware', '3': 'phishing'}

    index_tag_full = elk_index()

    # used to have a full view of AF tag data for data augmentation
    # for a current list, should run gettagdata.py periodically
    with open('data/tagdata.json', 'r') as tag_file:
        tag_dict = json.load(tag_file)

    listsize = len(autofocus_results['hits'])

    # interate through AF results to create dict key/values for each sample hash
    for listpos in range(0, listsize):
        keyhash = autofocus_results['hits'][listpos]['_source'][conf.hashtype]

        # Autofocus sending back bad data - ignore if not in source hash_list
        #source_list = get_search_list()

        # only for hash searches
        #if keyhash in source_list:

        hash_data_dict = {}


        # AFoutput is json output converted to python dictionary
        hash_data_dict['hashvalue'] = keyhash
        hash_data_dict['sample_found'] = True

        hash_data_dict['sha256hash'] = autofocus_results['hits'][listpos]['_source']['sha256']
        hash_data_dict['create_date'] = autofocus_results['hits'][listpos]['_source']['create_date']
        hash_data_dict['query_tag'] = query_tag
        hash_data_dict['query_time'] = str(start_time)

        # initial AF query to get sample data include sha256 hash and WF verdict
        # sha256 is required for sig queries; does not support md5 or sha1
        verdict_num = autofocus_results['hits'][listpos]['_source']['malware']
        verdict_text = malware_values[str(verdict_num)]
        hash_data_dict['verdict'] = verdict_text

        if 'filetype' in autofocus_results['hits'][listpos]['_source']:
            filetype = autofocus_results['hits'][listpos]['_source']['filetype']
            hash_data_dict['filetype'] = filetype
            if filetype in filetypetags:
                hash_data_dict['filetype_group'] = filetypetags[filetype]
            else:
                hash_data_dict['filetype_group'] = 'NewTypeEh'
        else:
            hash_data_dict['filetype'] = 'Unknown'
            hash_data_dict['filetype_group'] = 'Unknown'

        if 'tag' in autofocus_results['hits'][listpos]['_source']:

            hash_data_dict['all_tags'] = autofocus_results['hits'][listpos]['_source']['tag']

            priority_tags_public = []
            priority_tags_name = []
            tag_classes = []
            hash_data_dict['tag_array'] = {}
            hash_data_dict['exploit_data'] = []
            malware_tags = []
            campaign_tags = []
            actor_tags = []
            exploit_tags = []

            for tag in hash_data_dict['all_tags']:

                if 'tag_class' in tag_dict['_tags'][tag]:

                    tag_class = tag_dict['_tags'][tag]['tag_class']
                    tag_name = tag_dict['_tags'][tag]['tag_name']
                    if tag_class in ('malware_family', 'campaign', 'actor', 'exploit'):
                        priority_tags_public.append(tag)
                        priority_tags_name.append(tag_name)

                        if tag_class not in tag_classes:
                            tag_classes.append(tag_class)

                        # experimental to see if I can get all tag data added here for search and visuals
                        #hash_data_dict['tag_array'][tag] = tag_dict['_tags'][tag]

                        # create class specific list of tags for query and display
                        if tag_class == 'malware_family':
                            malware_tags.append(tag_name)
                        elif tag_class == 'campaign':
                            campaign_tags.append(tag_name)
                        elif tag_class == 'actor':
                            actor_tags.append(tag_name)
                        elif tag_class == 'exploit':
                            exploit_tags.append(tag_name)

                    hash_data_dict['priority_tags_public'] = priority_tags_public
                    hash_data_dict['priority_tags_name'] = priority_tags_name
                    hash_data_dict['tag_classes'] = tag_classes
                    hash_data_dict['malware_tags'] = malware_tags
                    hash_data_dict['campaign_tags'] = campaign_tags
                    hash_data_dict['actor_tags'] = actor_tags
                    hash_data_dict['exploit_tags'] = exploit_tags

                if 'tag_groups' in tag_dict['_tags'][tag]:
                    taggroups = []
                    for group in tag_dict['_tags'][tag]['tag_groups']:
                        if group not in taggroups:
                            taggroups.append(group['tag_group_name'])

                    hash_data_dict['tag_groups'] = taggroups

                # get CVE specific tag info and query against the fw exploit sig data
                # note: there are many exploits tags that don't have CVE values and no way to readily correlate
                if conf.get_exploits is True:
                    if 'CVE' in tag:

                        cve_value = tag.split('.')[1]
                        exploit_dict = {}
                        exploit_dict['cve_value'] = cve_value

                        if cve_value in exploits:
                            exploit_dict['threat name'] = exploits[cve_value]['Threat Name']
                            exploit_dict['category'] = exploits[cve_value]['Category']
                            exploit_dict['severity'] = exploits[cve_value]['Severity']

                        else:
                            exploit_dict['threat name'] = 'Unknown'
                            exploit_dict['category'] = 'Unknown'
                            exploit_dict['severity'] = 'Unknown'

                        hash_data_dict['exploit_data'].append(exploit_dict)

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

        # only for hash searches
        #else:
        #    print('Ignoring unexpected hash found: ' + keyhash)

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

    missing_sample_date = start_time.strftime('%Y-%m-%dT%H:%M:%S')

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
            samples_notfound_dict['create_date'] = missing_sample_date
            samples_notfound_dict['verdict'] = 'No Sample Found'

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

    # for sig search only lookup coverage for samples found in samples search
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


def quick_stats(query_tag):

    '''
    capture quick statistics for samples, verdicts, sig coverage
    and display to terminal
    :param query_tag: reference description for this script run
    :return:
    '''

    hash_counters = {}
    hash_count_values = ['total samples', 'malware', 'mal_inactive_sig',
                         'mal_active_sig', 'mal_no_sig', 'grayware', 'benign',
                         'phishing', 'no sample found']

    for value in hash_count_values:
        hash_counters[value] = 0

    # get the full json output file will all post-run sample data
    with open(f'{conf.out_pretty}/hash_data_pretty_{query_tag}_sigs.json', 'r') as samplesfile:
        samples_dict = json.load(samplesfile)


    listsize = len(samples_dict['samples'])
    hash_counters['total samples'] = listsize

    # iterate through each sample dict in the json samples list
    for listpos in range(0, listsize):

        sample_data = samples_dict['samples'][listpos]

        # counter updates for WF verdicts
        if sample_data['verdict'] == 'malware':
            hash_counters['malware'] += 1
        if sample_data['verdict'] == 'grayware':
            hash_counters['grayware'] += 1
        if sample_data['verdict'] == 'benign':
            hash_counters['benign'] += 1
        if sample_data['verdict'] == 'phishing':
            hash_counters['phishing'] += 1
        if sample_data['verdict'] == 'No Sample Found':
            hash_counters['no sample found'] += 1

        # counter updates for sig coverage
        if sample_data['verdict'] == 'malware':
            if sample_data['wf_av_sig_sig_state'] == 'active':
                hash_counters['mal_active_sig'] += 1
            if sample_data['wf_av_sig_sig_state'] == 'inactive':
                hash_counters['mal_inactive_sig'] += 1
            if sample_data['wf_av_sig_sig_state'] == 'none':
                hash_counters['mal_no_sig'] += 1

    print('=' * 80)
    print(f"Quick stats summary for {query_tag}\n")
    print(f"Total samples queried: {hash_counters['total samples']}")
    print(f"Samples not found in Autofocus: {hash_counters['no sample found']}")
    print('-' * 80)
    print('Verdicts')
    print(f"malware:  {hash_counters['malware']}")
    print(f"phishing:  {hash_counters['phishing']}")
    print(f"grayware:  {hash_counters['grayware']}")
    print(f"benign:  {hash_counters['benign']}")
    print('-' * 80)
    print('Signature coverage for malware verdicts')
    print(f"active:  {hash_counters['mal_active_sig']}")
    print(f"inactive:  {hash_counters['mal_inactive_sig']}")
    print(f"no sig:  {hash_counters['mal_no_sig']}")
    print('=' * 80)


def main():

    # python skillets currently use CLI arguments to get input from the operator / user. Each argparse argument long
    # name must match a variable in the .meta-cnc file directly
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--api_key", help="Autofocus API key", type=str)
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()
        exit(1)

    api_key = args.api_key

    '''search_data main module'''
    search_list_all = []

    # for longer lists may have to break list in 1000 size pieces
    # for autofocus type queries on do a single search
    numsearches = 1

    query_tag = input('Enter brief tag name for this data: ')
    start_time = datetime.now()
    listend = -1
    ok_to_get_sigs = True

    if conf.get_exploits is True:
        exploit_dict = clean_exploit_data()
        query_list = create_cve_list()
    else:
        exploit_dict = {}

    # refresh tag data list
    # the value sent to Autofocus should >> than current tag lists to set page count
    # as of 2019-05-16 list size is ~2900 items
    if conf.gettagdata == 'yes':
        tag_query(api_key)

    # check for output dirs and created if needed
    output_dir(conf.out_estack)
    output_dir(conf.out_pretty)

    if conf.onlygetsigs != 'yes':

        if conf.querytype == 'hash':
            # supported conf.hashtypes are: md5, sha1, sha256
            if conf.hashtype != 'md5' and conf.hashtype != 'sha1' and conf.hashtype != 'sha256':
                print('\nOnly hash types md5, sha1, or sha256 are supported')
                print('correct in conf.py and try again')
                sys.exit(1)

        if conf.querytype in ['hash', 'threat', 'domain']:
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

            searchrequest = multi_query(search_list, api_key)

            #get query results and parse output
            scantype_query_results(searchrequest, start_time, query_tag, search, api_key, exploit_dict)

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
        if conf.querytype == 'hash':
            missing_samples(query_tag, start_time)

    if conf.getsigdata == 'yes' and ok_to_get_sigs is True:
            get_sig_data(query_tag, start_time)

    if conf.querytype == 'autofocus':
            print(conf.af_query)

    # print out summary stats to terminal console
    if conf.querytype == 'hash' and conf.getsigdata == 'yes':
        quick_stats(query_tag)

    # print out the elasticSearch bulk load based on the tag and thus filename
    print('\nuse the curl command to load estack data to elasticSearch')
    print('either ignore -u if no security features used or append with elasticSearch username and password\n')
    print(f'curl -s -XPOST \'http://{conf.elastic_url_port}/_bulk\' --data-binary @out_estack/hash_data_estack_{query_tag}_nosigs.json -H \"Content-Type: application/x-ndjson\" -u user:password\n\n')

if __name__ == '__main__':
    main()
