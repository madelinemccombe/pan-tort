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

Reads in a list of samples hashes or af_query as json

Output of session stat data

Outputs are formatted for both bulk load into Elasticsearch and
readable 'pretty format' json

Outputs are stored in the out_estack and out_pretty directories

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import argparse
import sys
import os
from os import path
import csv
import json
import time
from geopy.geocoders import GoogleV3
from geopy.exc import GeocoderServiceError, GeocoderQueryError, GeocoderQuotaExceeded
from datetime import datetime
import requests

# adding shared dir for imports
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(here, '../shared')))

# using to create global var for input api keys
keys = None

# script to create or update the tagdata.json list from Autofocus
from gettagdata import tag_query

# local imports for static data input
import conf
from filetypedata import filetypetags


def get_geo(country_code, geo_key):
    '''
    input country and return longitude, latitude values
    :param country: country name
    :param geo_key: api key used by Google mapping
    :return:
    '''

    # check if file exists and if not create it
    if not path.isfile('data/geoData.csv'):
        with open('data/geoData.csv', 'w') as geo_file:
            geo_writer = csv.writer(geo_file, delimiter=',')
            geo_writer.writerow(['country_code', 'latitude', 'longitude'])

    # check local file cache if country already geocoded
    with open('data/geoData.csv', 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if row[0] == country_code:
                latitude = float(row[1])
                longitude = float(row[2])
                return latitude, longitude

    # using GoogleV3 for geo lookups
    geolocator = GoogleV3(api_key=geo_key)

    try:
        location = geolocator.geocode(components={'country' : country_code}, exactly_one=True)
        # print(f'location is {country_code}')
        # print(f'with lat: {location.latitude} and lon: {location.longitude}')

        try:
            with open('data/geoData.csv', 'a') as geo_file:
                geo_writer = csv.writer(geo_file, delimiter=',')
                geo_writer.writerow([country_code, location.latitude, location.longitude])
            return location.latitude, location.longitude

        except:
            print('  ***** geocode lon-lat error - writing to geocoding-error.csv *****')
            print(f'  Failed with message: no lon or lat for country {country_code}')

            # append to the error file to see quick view of bad countries
            with open('geocoding-error.csv', 'a') as uhoh:
                geo_writer = csv.writer(uhoh, delimiter=',')
                geo_writer.writerow([datetime.now(), country_code, 0, 0])

            # append to the good file to avoid recurring geo lookups
            with open('data/geoData.csv', 'a') as geo_file:
                geo_writer = csv.writer(geo_file, delimiter=',')
                geo_writer.writerow([country_code, 0, 0])
            return 0, 0

    except (GeocoderServiceError, GeocoderQueryError, GeocoderQuotaExceeded) as error_message:
        print('  ***** geocode lookup error - writing to geocoding-error.csv *****')
        print('  Failed with message: {0}'.format(error_message))
        with open('geocoding-error.csv', 'a') as uhoh:
            geo_writer = csv.writer(uhoh, delimiter=',')
            geo_writer.writerow([datetime.now(), country_code, 1, 1])

    return 0, 0

def elk_index():
    '''
    set up elasticsearch bulk load index
    :param conf.elk_index_name: name of data index in elasticsearch
    :return: index tag to write as line in the output json file
    '''

    index_tag_full = {}
    index_tag_inner = {}
    index_tag_inner['_index'] = conf.elk_index_name_session
    index_tag_inner['_type'] = conf.elk_index_name_session
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

    # query is json format in conf.py as export from the AF web UI
    if conf.querytype == 'autofocus':
        query = conf.af_query
    
    print(query)

    search_values = {"apiKey": api_key,
                      "query": query,
                      "size": 4000,
                      # "scope": "global",
                      "type": "scan",
                      # "artifactSource": "af"
                     }


    headers = {"Content-Type": "application/json"}
    search_url = f'https://{conf.hostname}/api/v1.0/sessions/search'

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


def scantype_query_results(search_dict, start_time, query_tag, search, api_key, geo_key):

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
    stall_count = 1
    totalsamples = 0

    running_total = []
    running_length = []

    # looping across 1000 element input lists requires a file read if > 1 loops
    if search == 1:
        all_sample_dict = {}
        all_sample_dict['sessions'] = []
    else:
        with open(f'{conf.out_pretty}/session_data_pretty_{query_tag}_nosigs.json', 'r') as hash_file:
            all_sample_dict = json.load(hash_file)

    while search_progress != 'FIN':

        time.sleep(5)
        try:
            # results_url = f'https://{conf.hostname}/api/v1.0/samples/results/' + cookie
            results_url = f'https://{conf.hostname}/api/v1.0/sessions/results/' + cookie
            headers = {"Content-Type": "application/json"}
            results_values = {"apiKey": api_key}
            results = requests.post(results_url, headers=headers, data=json.dumps(results_values))
            results.raise_for_status()
        except requests.exceptions.HTTPError:
            print(results)
            print(results.text)
            print('\nCorrect errors and rerun the application\n')
            sys.exit()

        # testing only to see json dict fields
        autofocus_results = results.json()
        with open('test.txt', 'w') as file:
            file.write(json.dumps(autofocus_results, indent=4, sort_keys=False) + "\n")

        if 'total' in autofocus_results:

            running_total.append(autofocus_results['total'])
            running_length.append(len(autofocus_results['hits']))

            if autofocus_results['total'] != 0:
                # parse data and output estack json elements
                # return is running dict of all samples for pretty json output
                all_sample_dict = parse_sample_data(autofocus_results, start_time, index, query_tag, all_sample_dict, search, geo_key)
                with open(f'{conf.out_pretty}/session_data_pretty_{query_tag}_nosigs.json', 'w') as hash_file:
                    hash_file.write(json.dumps(all_sample_dict, indent=2, sort_keys=False) + "\n")
                index += 1

                print(f'Results update for page {index}: {query_tag}\n')
                print(f"samples found so far: {autofocus_results['total']}")
                print(f"Search percent complete: {autofocus_results['af_complete_percentage']}%")
                print(f"samples processed in this batch: {len(autofocus_results['hits'])}")
                totalsamples_old = totalsamples
                totalsamples = sum(running_length)
                print(f'total samples processed: {totalsamples}\n')
                minute_pts_rem = autofocus_results['bucket_info']['minute_points_remaining']
                daily_pts_rem = autofocus_results['bucket_info']['daily_points_remaining']
                print(f'AF quota update: {minute_pts_rem} minute points and {daily_pts_rem} daily points remaining')
                elapsedtime = datetime.now() - start_time
                print(f'Elasped run time is {elapsedtime}')
                print('=' * 80)

                # checking if the search has stalled and can end early
                if totalsamples_old == totalsamples:
                    stall_count += 1
                else:
                    stall_count = 1

            if autofocus_results['af_in_progress'] is False :
                search_progress = 'FIN'

            if stall_count == conf.stall_stop:
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


def parse_sample_data(autofocus_results, start_time, index, query_tag, session_data_dict_pretty, search, geo_key):

    '''
    parse the AF reponse and augment the data with file type, tag, malware
    then write 2 files: pretty json and estack for bulk load into elasticsearch
    :param autofocus_results: array of data from AF multi-query response
    :param start_time: time script started; used to track run time
    :param index: note which cycle through the search block for file w or a
    :param query_tag: identifier for this script run used as estack tag
    :param search: for multi-page search to denote which 1000 block being used
    :param session_data_dict_pretty: master set of data to write out to json
    :return: update dictionary with sample data
    '''

    # mapping of tag # to text name
    # malware_values = {'0': 'benign', '1': 'malware', '2': 'grayware', '3': 'phishing'}

    index_tag_full = elk_index()

    # used to have a full view of AF tag data for data augmentation
    # for a current list, should run gettagdata.py periodically
    with open('data/tagdata.json', 'r') as tag_file:
        tag_dict = json.load(tag_file)

    listsize = len(autofocus_results['hits'])

    # interate through AF results to create dict key/values for each sample hash
    for listpos in range(0, listsize):
        session_id = autofocus_results['hits'][listpos]['_id']

        # Autofocus sending back bad data - ignore if not in source hash_list
        # source_list = get_search_list()

        # only for hash searches
        #if keyhash in source_list:

        session_data_dict = {}

        # AFoutput is json output converted to python dictionary
        session_data_dict['session_id'] = session_id

        fieldList = [
            'sha256','tstamp',
            'device_industry','region',
            'dst_countrycode', 'dst_country', 'dst_port',
            'src_countrycode', 'src_country', 'src_port',
            'upload_src', 'app', 'status'
        ]

        for field in fieldList:
            if field in autofocus_results['hits'][listpos]['_source']:
                session_data_dict[field] = autofocus_results['hits'][listpos]['_source'][field]

                # get lat and long coordinates for src and dst countries
                if field == 'dst_countrycode':
                    session_data_dict['dst_lat'], session_data_dict['dst_lon'] = \
                        get_geo(autofocus_results['hits'][listpos]['_source'][field], geo_key)

                if field == 'src_countrycode':
                    session_data_dict['src_lat'], session_data_dict['src_lon'] = \
                        get_geo(autofocus_results['hits'][listpos]['_source'][field], geo_key)

        session_data_dict['query_tag'] = query_tag
        session_data_dict['query_time'] = str(start_time)

        # initial AF query to get sample data include sha256 hash and WF verdict
        # sha256 is required for sig queries; does not support md5 or sha1
        # verdict_num = autofocus_results['hits'][listpos]['_source']['malware']
        # verdict_text = malware_values[str(verdict_num)]
        # hash_data_dict['verdict'] = verdict_text

        if 'tag' in autofocus_results['hits'][listpos]['_source']:

            session_data_dict['all_tags'] = autofocus_results['hits'][listpos]['_source']['tag']

            priority_tags_public = []
            priority_tags_name = []
            tag_classes = []
            session_data_dict['tag_array'] = {}
            malware_tags = []
            campaign_tags = []
            actor_tags = []
            exploit_tags = []

            for tag in session_data_dict['all_tags']:

                if 'tag_class' in tag_dict['_tags'][tag]:

                    tag_class = tag_dict['_tags'][tag]['tag_class']
                    tag_name = tag_dict['_tags'][tag]['tag_name']
                    if tag_class in ('malware_family', 'campaign', 'actor', 'exploit'):
                        priority_tags_public.append(tag)
                        priority_tags_name.append(tag_name)

                        if tag_class not in tag_classes:
                            tag_classes.append(tag_class)

                        # experimental to see if I can get all tag data added here for search and visuals
                        # session_data_dict['tag_array'][tag] = tag_dict['_tags'][tag]

                        # create class specific list of tags for query and display
                        if tag_class == 'malware_family':
                            malware_tags.append(tag_name)
                        elif tag_class == 'campaign':
                            campaign_tags.append(tag_name)
                        elif tag_class == 'actor':
                            actor_tags.append(tag_name)
                        elif tag_class == 'exploit':
                            exploit_tags.append(tag_name)

                    session_data_dict['priority_tags_public'] = priority_tags_public
                    session_data_dict['priority_tags_name'] = priority_tags_name
                    session_data_dict['tag_classes'] = tag_classes
                    session_data_dict['malware_tags'] = malware_tags
                    session_data_dict['campaign_tags'] = campaign_tags
                    session_data_dict['actor_tags'] = actor_tags
                    session_data_dict['exploit_tags'] = exploit_tags

                if 'tag_groups' in tag_dict['_tags'][tag]:
                    taggroups = []
                    for group in tag_dict['_tags'][tag]['tag_groups']:
                        if group not in taggroups:
                            taggroups.append(group['tag_group_name'])

                    session_data_dict['tag_groups'] = taggroups

        # this creates a json format with first record as samples then appended json list entries
        # proper json format to read the file in during run to append with new data
        session_data_dict_pretty['sessions'].append(session_data_dict)

        # Write dict contents to running file both estack and pretty json versions
        if index == 1 and listpos == 0 and search == 1:
            with open(f'{conf.out_estack}/session_data_estack_{query_tag}_nosigs.json', 'w') as session_file:
                session_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                session_file.write(json.dumps(session_data_dict, indent=None, sort_keys=False) + "\n")
        else:
            with open(f'{conf.out_estack}/session_data_estack_{query_tag}_nosigs.json', 'a') as session_file:
                session_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                session_file.write(json.dumps(session_data_dict, indent=None, sort_keys=False) + "\n")

        # only for hash searches
        #else:
        #    print('Ignoring unexpected hash found: ' + keyhash)

    return session_data_dict_pretty


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
    with open(f'{conf.out_pretty}/session_data_pretty_{query_tag}_nosigs.json', 'r') as samplesfile:
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
            with open(f'{conf.out_estack}/session_data_estack_{query_tag}_nosigs.json', 'a') as hash_file:
                hash_file.write(json.dumps(index_tag_full, indent=None, sort_keys=False) + "\n")
                hash_file.write(json.dumps(samples_notfound_dict, indent=None, sort_keys=False) + "\n")

            samples_dict['samples'].append(samples_notfound_dict)

    with open(f'{conf.out_pretty}/session_data_pretty_{query_tag}_nosigs.json', 'w') as hash_file:
        hash_file.write(json.dumps(samples_dict, indent=4, sort_keys=False) + "\n")


def main():

    # python skillets currently use CLI arguments to get input from the operator / user. Each argparse argument long
    # name must match a variable in the .meta-cnc file directly
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--api_key", help="Autofocus API key", type=str)
    parser.add_argument("-g", "--geo_key", help="Google API key", type=str)
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()
        exit(1)

    api_key = args.api_key
    geo_key = args.geo_key

    '''search_data main module'''
    search_list_all = []

    # for longer lists may have to break list in 1000 size pieces
    # for autofocus type queries on do a single search
    numsearches = 1

    query_tag = input('Enter brief tag name for this data: ')
    start_time = datetime.now()
    listend = -1
    ok_to_get_sigs = True

    # refresh tag data list
    if conf.gettagdata == 'yes':
        tag_query(api_key)

    # check for output dirs and created if needed
    output_dir(conf.out_estack)
    output_dir(conf.out_pretty)


    if conf.querytype == 'hash':
        # supported conf.hashtypes are: md5, sha1, sha256
        if conf.hashtype != 'md5' and conf.hashtype != 'sha1' and conf.hashtype != 'sha256':
            print('\nOnly hash types md5, sha1, or sha256 are supported')
            print('correct in conf.py and try again')
            sys.exit(1)

    if conf.querytype == 'hash':
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
        scantype_query_results(searchrequest, start_time, query_tag, search, api_key, geo_key)

    # check that the output sigs file exists if AF hits 1= 0
    # if no file, check that hashtype in conf.py matches hashlist.txt type
    try:
        with open(f'{conf.out_pretty}/session_data_pretty_{query_tag}_nosigs.json', 'r'):
            pass
    except IOError as nofile_error:
        print(nofile_error)
        print(f'Unable to open out_pretty/session_data_pretty_{query_tag}_nosigs.json')
        print('This file is output from the initial sample search and read in to create a sig coverage output')
        print('If hits are expected check that the hashtype in conf.py matches the hashes in hash_list.txt')
        ok_to_get_sigs = False

    # find AF sample misses and add to the estack json file as not found
    if conf.querytype == 'hash':
        missing_samples(query_tag, start_time)

    if conf.querytype == 'autofocus':
            print(conf.af_query)

    # print out the elasticSearch bulk load based on the tag and thus filename
    print('\nuse the curl command to load estack data to elasticSearch')
    print('either ignore -u if no security features used or append with elasticSearch username and password\n')
    print(f'curl -s -XPOST \'http://{conf.elastic_url_port}/_bulk\' --data-binary @out_estack/session_data_estack_{query_tag}_nosigs.json -H \"Content-Type: application/x-ndjson\" -u user:password\n\n')

if __name__ == '__main__':
    main()
