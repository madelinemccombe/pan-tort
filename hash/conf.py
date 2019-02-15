hostname = 'autofocus.paloaltonetworks.com'
# querytype is autofocus for exported queries or hash when reading from hash list
querytype = 'hash'
# used for hash inputs; leave as default even if not using
inputfile = 'hash_list.txt'
hashtype = 'sha256'
elk_index_name = 'hash-data'
out_estack = 'out_estack'
out_pretty = 'out_pretty'
# extend the data parsing to include a second search for sig coverage
getsigdata = 'yes'
# for testing to use existing pretty json output file and skip sample search
onlygetsigs = 'no'
gettagdata = 'yes'
# edit the query for each search
# you can copy-paste by creating a query in Autofocus and exporting using the GUI 'Export Search'
af_query = {"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1},{"field":"session.app","operator":"is in the list","value":["ms-ds-smbv2","ms-ds-smbv1","ms-ds-smbv3"]},{"field":"sample.create_date","operator":"is after","value":["2018-01-01T00:01:00","2018-09-17T03:44:00"]}]}
# placeholder so af_query no EOF - paste cheat