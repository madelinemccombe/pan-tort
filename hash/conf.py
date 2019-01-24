hostname = 'autofocus.paloaltonetworks.com'
# querytype is autofocus for exported queries or hash when reading from hash list
querytype = 'hash'
# used for hash inputs; leave as default even if not using
inputfile = 'hash_list.txt'
hashtype = 'md5'
elk_index_name = 'hash-data'
out_estack = 'out_estack'
out_pretty = 'out_pretty'
# extend the data parsing to include a second search for sig coverage
getsigdata = 'yes'
# for testing to use existing pretty json output file and skip sample search
onlygetsigs = 'no'
gettagdata = 'no'
# edit the query for each search
# you can copy-paste by creating a query in Autofocus and exporting using the GUI 'Export Search'
af_query = {"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1},{"field":"session.app","operator":"is","value":"ftp"},{"field":"sample.create_date","operator":"is after","value":["2018-01-01T00:00:00","2018-11-05T23:59:59"]},{"field":"session.upload_src","operator":"is not","value":"Manual API"}]}
# placeholder so af_query no EOF - paste cheat