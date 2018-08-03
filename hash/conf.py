hostname = 'autofocus.paloaltonetworks.com'
# querytype is autofocus for exported queries or hash when reading from hash list
querytype = 'hash'
# used for hash inputs; leave as default even if not using
hashfile = 'hash_list.txt'
hashtype = 'sha256'
elk_index_name = 'hash-data'
# extend the data parsing to include a second search for sig coverage
get_sig_data = 'yes'
# edit the query for each search
# you can copy-paste by creating a query in Autofocus and exporting using the GUI 'Export Search'
af_query = {"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1},{"field":"sample.filetype","operator":"is in the list","value":["DLL64","Microsoft Excel 97 - 2003 Document"]},{"field":"sample.create_date","operator":"is in the range","value":["2018-07-09T00:00:00","2018-07-13T23:59:59"]},{"field":"session.upload_src","operator":"is not","value":"Manual API"}]}
# placeholder so af_query no EOF - paste cheat