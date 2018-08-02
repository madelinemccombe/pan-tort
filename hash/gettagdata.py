####!/usr/bin/env python3
"""
hash_data reads a list of md5 hash strings and performs 2 Autofocus api
queries to get verdict/filetype and then signature coverage data
This provides contextual information in test environments beyond just a hash miss
"""
import sys
import json
import requests

from af_api import api_key
from conf import hostname


def tag_query(total):

    """
    tag query into autofocus to get a complete tag list
    """

    # set the number of iterations based on total tags and limit of 200 tags per response
    AFpages = int(round(total/200))
    tag_dict = {}
    tag_dict['_tags'] = {}

    for page in range(0, AFpages+1, 1):

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
            print(f'Getting tag data at page {page}')
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


    return

if __name__ == '__main__':
    tag_query(2292)
