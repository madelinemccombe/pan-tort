####!/usr/bin/env python3
"""
hash_data reads a list of md5 hash strings and performs 2 Autofocus api
queries to get verdict/filetype and then signature coverage data
This provides contextual information in test environments beyond just a hash miss
"""
import sys
import json
import requests

from conf import hostname

def get_tag_count(api_key):

    print('=' * 80)
    print('get total number of tags in Autofocus')
    print('tag data query is limited to 200 tags; each page query gets a block of 200 tags\n')

    # dummy query to make the search work - not limited to Ransomware
    query = {"field":"tag_group","operator":"is","value":"Ransomware"}

    search_values = {"apiKey": api_key,
                        "query": query,
                        "pageSize": 200,
                        "pageNum": 1,
                        "scope": "visible",
                    }

    headers = {"Content-Type": "application/json"}
    search_url = f'https://{hostname}/api/v1.0/tags'

    try:
        search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
        search.raise_for_status()
    except requests.exceptions.HTTPError:
        print(search)
        print(search.text)
        print('\nCorrect errors and rerun the application\n')
        sys.exit()

    search_dict = json.loads(search.text)
    total = search_dict['total_count']
    print(f'found {total} tags')

    return(search_dict['total_count'])

def tag_query(api_key):

    """
    tag query into autofocus to get a complete tag list
    :param total: max number of tag items expected; should be >> current size
    """
    # get total number of tags
    total = get_tag_count(api_key)

    # set the number of iterations based on total tags and limit of 200 tags per response
    AFpages = int(round(total/200))
    tag_dict = {}
    tag_dict['_tags'] = {}

    print('=' * 80)
    print('Updating local tag data from Autofocus tag and tag group lists...\n')


    for page in range(0, AFpages+1, 1):

        # dummy query to make the search work - not limited to Ransomware
        query = {"field":"tag_group","operator":"is","value":"Ransomware"}

        search_values = {"apiKey": api_key,
                         "query": query,
                         "pageSize": 200,
                         "pageNum": page,
                         "scope": "visible",
                        }

        headers = {"Content-Type": "application/json"}
        search_url = f'https://{hostname}/api/v1.0/tags'

        try:
            search = requests.post(search_url, headers=headers, data=json.dumps(search_values))
            print(f'Getting tag data at page {page} of {AFpages}')
            search.raise_for_status()
        except requests.exceptions.HTTPError:
            print(search)
            print(search.text)
            print('\nCorrect errors and rerun the application\n')
            sys.exit()

        search_dict = json.loads(search.text)

        for tag in search_dict['tags']:
            tagname = tag['public_tag_name']
            tag_dict['_tags'][tagname] = tag


    with open('tagdata.json', 'w') as file:
        file.write(json.dumps(tag_dict, indent=2, sort_keys=False) + "\n")

    print('\ntag data refresh complete and stored in tagdata.json')


    return

if __name__ == '__main__':
    # set to >> max number of tags to ensure we pull them all
    tag_query(api_key)
