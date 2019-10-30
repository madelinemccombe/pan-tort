hostname = 'autofocus.paloaltonetworks.com'
# querytype is autofocus for exported queries or hash when reading from hash list
querytype = 'autofocus'
# used for hash inputs; leave as default even if not using
inputfile = 'hash_list.txt'
elk_index_name = 'hash-data'
hashtype = 'sha256'
out_estack = 'out_estack'
out_pretty = 'out_pretty'
# extend the data parsing to include a second search for sig coverage
getsigdata = 'no'
# for testing to use existing pretty json output file and skip sample search
onlygetsigs = 'no'
gettagdata = 'no'
# adds exploit details to the data for exploit specific queries
get_exploits = False
inputfile_exploits = 'exploits.csv'
# edit the query for each search
# you can copy-paste by creating a query in Autofocus and exporting using the GUI 'Export Search'
af_query = {"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1},{"field":"sample.create_date","operator":"is after","value":["2019-10-30T00:00:00","2019-10-30T00:00:00"]},{"field":"sample.tag_class","operator":"is in the list","value":["exploit"]}]}

# placeholder so af_query no EOF - paste cheat