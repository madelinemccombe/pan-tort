# used in the url to connect to autofocus
hostname = 'autofocus.paloaltonetworks.com'
# file that contains the list of hash values
inputfile = 'hash_list.txt'
# hashtype options are md5, sha256, or sha1
hashtype = 'md5'
# used to map to the index in elasticsearch
elk_index_name = 'hash-data'
# used for secondary lookups for get signature coverage data in AF
# only set to no for testing or quick queries for tag/filetype data
getsigdata = 'yes'