Pan-tort ElasticSearch data loads
=================================

Run the Autofocus sample queries and prep for ElasticSearch bulk load

Each curl is to delete and then add new data to the index.


Sample data bulk load
---------------------

Loads can be addititive since Elasticsearch will create unique documents ids when loaded

.. highlight:: bash

Delete existing data in the index

::
   curl -XDELETE http://localhost:9200/{{elk_index_name}}


Generic format to add new data to the index as a bulk load

::
   curl -s -XPOST 'http://localhost:9200/_bulk' --data-binary @{filename}.json -H "Content-Type: application/x-ndjson"


Format filename used with pan-tort

::
   curl -s -XPOST 'http://localhost:9200/_bulk' --data-binary @hash_data_estack.json -H "Content-Type: application/x-ndjson"


My data indexes and file
------------------------


.. highlight:: bash

This can be used as a local workspace for load specific index and filename

Delete existing data in the index

::
    curl -XDELETE http://localhost:9200/sampleindex

::
    curl -s -XPOST 'http://localhost:9200/_bulk' --data-binary @hash_data_estack_cryptominer_mar25231_nosigs.json -H "Content-Type: application/x-ndjson"


Elasticsearch delete by query example
-------------------------------------

POST hash-data/_delete_by_query
{
        "size": 10000,
        "_source": "query_tag",
"query": {
        "match" : {
            "query_tag" : "cryptominer_apr18"
        }
    }
}
