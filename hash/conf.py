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
getsigdata = 'no'
# for testing to use existing pretty json output file and skip sample search
onlygetsigs = 'no'
gettagdata = 'no'
# edit the query for each search
# you can copy-paste by creating a query in Autofocus and exporting using the GUI 'Export Search'
af_query = {"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1},{"field":"sample.create_date","operator":"is after","value":["2019-04-01T00:00:00","2019-05-31T00:00:00"]},{"field":"sample.filetype","operator":"is","value":"Android APK"},{"field":"sample.tag_class","operator":"is in the list","value":["actor","campaign","malware_family","exploit"]}]}
# placeholder so af_query no EOF - paste cheat