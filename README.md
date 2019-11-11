# User Guide for AF Queries

This tool currently provides support for 3 types of queries:

1) sample query based on hash list inputs or AF json format query
2) session query based on hash list inputs or AF json format query
3) summary monthly tag group stastical data

The output is formatted primarily as json for bulk loads into ElasticSearch
without the use of logstash. This format is referenced as `estack` in lieu of
the 'pretty' format that a readable version of json.

## Autofocus (AF) scan search type

For the sample and session queries, a scan type search is used. This allows
the search results to scale to 200,000 samples or sessions using minimal points

An initial search is initiated to AF and a cookie value assigned. The cookie is used
to capture paged results, up to 1,000 results per page. The same cookie is used
to retrieve each page of results until all data has been collected from AF.

This type of search is noted with `type: scan` as part of the search values
information sent with the query.


## Repo Directory structure

The main code resides in the af_query directory. The shared directory includes
python snippets supporting searches and a misc directory with Kibana dashboard
samples.

### af_query directory

Houses the python code along with a `data` reference directory and three output
directories (out_estack, out_pretty, tag_group_stats_json).

#### conf.py

This is a variable input file referenced by the python code.

* hostname: autofocus url used for API queries
* elastic_url_port: ip address and port for the elasticSearch server
* querytype: `autofocus` or `hash` to denote query input source
* inputfile: input hash file name used if querytype=hash
* hashtype: type of hashes in the hash file if querytype=hash
* elk_index_name: sample search index used in elasticSearch
* elk_index_name: session search index used in elasticSearch
* out_estack: directory name for bulk-load formatted for sample and session search output data
* out_pretty: directory name for readable json output files
* getsigdata: yes/no option; `yes` will get sig coverage data for all file hashes
* onlygetsigs: yes/no option; `yes` will bypass the autofocus query and read the pretty json file
* gettagdata: yes/no option; `yes` will refresh the tag list along with associated attributes
* get_exploits: True/False option; if True will augment exploit data with firewall sig information
* inputfile_exploits: file name in the data dir for the exploit csv data from the firewall
* af_query: the json-formatted search query; can be exported from the autofocus UI
* start_month: used for the tag-group stats; how far back in time for the search
* start_year: used for the tag-group stats; how far back in time for the search
* stall_stop: for session searches, will stop the search if counters stop incrementing; bypass end of search delays



#### threat_data.py

This is a standard sample search using the Autofocus API. Uses -k to include
the Autofocus API Key.

```
python threat_data.py -k { autofocus api_key }
```

Requested input is a query_tag text string to mark this specific search and output.

Based on the querytype in the conf.py file will either read in a hash list
or use the af_query string to initiate a search.

All samples returned as results are then parsed and augmented with simplified file type names,
tag buckets by class, and addition of the query_tag input string.

The results are stored in the pretty and estack directories including the name of the query_tag.

If getsigdata is 'yes' in the conf.py file, an additional set of searches are performed,
one per hash, to add the signature coverage data to each record. Since the queries
are one per hash, care must be given to monitor per-minute and especially per-day
AF point quotas for larger searches.

Then the query is complete, the output includes a curl command to bulk load
the data into ElasticSearch. Based on security settings a -u parameter may be
required with the access username:password.

#### session_data.py

This is a session search using the Autofocus API. Uses -k to include
the Autofocus API Key and -g to include the GoogleV3 geocode api key.

```
python threat_data.py -k { autofocus api_key } -g { GoogleV3 api key }
```

The function is the same as the sample search with a hash list or af_query input,
tag associations and buckets, and output to the pretty and estack directories.

The session data will also geocode the source and destination countries if
part of the session results. A cache of country lon/lat information is kept
in the data directory as `geoData.csv`. If a country geocode has happened,
then the local data is used to offload extensive use of the geocode API.

Any goecode errors are captured, once per country, and stored in the file
`geocoding-error.csv` along with a timestamp. This will show country codes
no found as part of the GoogleV3 lookup.

Session data can contain private information. Therefore not all session values
are captured in the data. Only source/destination ports, countries are captured
along with industry, tags, and application name. No company names, email or file information,
or company-specific details are included.

Then the query is complete, the output includes a curl command to bulk load
the data into ElasticSearch. Based on security settings a -u parameter may be
required with the access username:password.

#### summary_stats_tag_group.py

This code is for monthly stats specific to the tag_group list. These are stat
counters to look at higher level trends. The code iterates over each group and
month-year getting a total sample count.

When run the list of tag-groups is autogenerated using a tag query. The output
is written to file groupList.txt in the data directory. This list is used for the
monthly iteration.

The start month and year is part of the conf.py file. This allows the user to
specific how far back in time to initiate the stats query.

### shared directory

The includes the gettagdata and filetype data python files.

#### gettagdata.py

This runs when the associated conf.py variable is 'yes'. Instead of as-needed
tag lookups for associated data, this is a proactive query to retrieve all
tag data using minimal points and time.

First a check is done to get the total number of tags. This will vary over time
and also based on access to private tag information. After the total is obtained,
A 200-tag per page iteration occurs to get all tag results. These are stored
locally as data/tagdata.json and referenced by the other queries.

#### filetypedata.py

This is a static dictionary file with all filetypes and a filegroup name.
Sample query results use this to associate simplified file names or groupings
with each sample. For example, PE and PE64 are grouped as 'PE' and long MS Office
names are shortened to just 'Excel' or 'Word'.









