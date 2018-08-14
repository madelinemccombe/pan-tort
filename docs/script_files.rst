Script files used in the Hash directory
=======================================

The hash toolkit has a small set of python files used to get contextual data from file samples/hashs.


hash_data_plus.py
-----------------

This is an updated version of the hash_data.py file that uses a multi-sample initial query to Autofocus.
A query to AF can send as many as 1,000 samples in a single request to save time and quota points.

The first data captured from this bulk query is file type, WF verdict, and malware family/group data.
Then for samples found in AF, analysis queries for sig coverage data are performed.

Input options are in the conf.py file that has initial default settings.

Output is sent to to the out_estack and out_pretty directories.

    * out_estack is json formatted for bulk loading into Elasticsearch

    * out_pretty is pulled back into python as a complete data set to augment with sig coverage data

The user is now prompted for a query_tag used in the output file names and as a field value in Elasticsearch.


hash_data.py
------------

This is the original query file with a simple hashtype prompt when running.

It is less optimal since uses one sample at a time. It is slower and uses more AF quota points.

The output is stateless using the sample file name each run, overwriting existing files.

hash_data.py does have a stats counter view and output whereas hash_data_plus.py is focus on estack loading.


gettagdata.py
-------------

This file should be run periodically to get the lastest set of tag and tag group data from AF.

Output writes to tagdata.json that is used by hash_data_plus.py to augment data with tag details.


filetypedata.py
---------------

A static file for reference that has the AF file type name mapped into a file group.

The file group can be used in Kibana visuals to simplify outputs.

As example, PE and PE64 are grouped as PE.

