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
Palo Alto Networks gettagdata.py

queries Autofocus to get a full list of tags and their tag groups

run gettagdata.py and output is tagdata.json

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import sys
import json
import requests

# local static values
from af_api import api_key
from conf import hostname


def tag_query(total):

    '''
    tag query into autofocus to get a complete tag list
    '''

    # set iteration size based on total tags and limit of 200 tags per response
    af_pages = int(round(total/200))
    tag_dict = {}
    tag_dict['_tags'] = {}

    for page in range(0, af_pages+1, 1):

        query = {"field":"tag_group", "operator":"is", "value":"Ransomware"}

        search_values = {"apiKey": api_key,
                         "query": query,
                         "pageSize": 200,
                         "pageNum": page,
                         "scope": "visible",
                        }

        headers = {"Content-Type": "application/json"}
        search_url = f'https://{hostname}/api/v1.0/tags'

        try:
            search = requests.post(search_url, headers=headers,
                                   data=json.dumps(search_values))
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


if __name__ == '__main__':
    tag_query(3000)
