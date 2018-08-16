Overview
========

Palo Alto Networks 'Test Output Research Tool' aka pan-tort

Pan-Tort is designed to help automate data capture for a list of MD5, SHA1, or SHA256 hashes that may have failed
a security performance test.

What pan-tort does
------------------

Instead of manually digging through various tools like Threatvault, Wildfire, or Autofocus to get contextual data
about the hashes, the user can input the list of hashes and have pan-tort query Autofocus for the following items:

    * Wildfire verdict (malware, phishing, grayware, or benign)

    * Hash file type

    * Autofocus malware family, actor, and campaign tag associations

    * Wildfire/AV signature names and status

    * DNS signature names and status

The responses are output in 3 ways:

    1. Simple console stats summary when the run is complete

    2. Elasticsearch load-ready json format with index attributes

    3. Readable 'pretty json' output format to scan through query results


Impacts to Autofocus API rate limits
------------------------------------

Pan-tort uses the Autofocus API which rate limits using a point system.
Each lookup uses points that count against per-minute and daily totals.

The maximum number of daily points per Autofocus API key is based on the license purchased. A standard license can
use up to 5,000 points per day while an unlimited license provides 100,000 points per day. All licenses are limited
to 200 points per minute.

The queries are designed to be low impact with the initial hash search for tag and file type data done as a single bulk
search. Initializing a query is 10 points, each subsequent check for results 1 point. Searches for signature coverage
use 2 points, 1 each for query and response.

As example, a typical pan-tort run with 100 hashes will use about 215 daily points. Per-minute point totals typically
range from 20-30 points based on query-response times.


Sample output views
-------------------

Summary Stats
~~~~~~~~~~~~~

If running from a terminal console, at the end of the run, a short summary of key stats is shown.

.. image:: images/summary_stats.png


Values in the summary stats:

    * Total samples queried: the number of hashes in the input list

    * Samples not found in Autofocus: the hash value is not found in Autofocus

    * Verdicts: based on Wildfire analysis verdict results

    * Signature coverage for malware verdicts

        + active: There is a WF/AV sig currently loaded in the firewall

        + inactive: A signature has been created and is not currently loaded in the firewall

        + no sig: no signature history for this file sample


Kibana dashboard
~~~~~~~~~~~~~~~~

The Kibana dashboard provides a more interactive view of the output data.

Pan-tort includes importable json elements for Kibana. Users can then extend visualizations and dashboard
as desired using the same source data.

.. image:: images/dashboard.png


Text json output
~~~~~~~~~~~~~~~~

For quick analysis or sharing, there is a pretty-format json file with all results data. This detailed data extends
beyond the summary stats to include malware family and groups, file types for each sample, and signature details
such as threatname, DNS domains, and create dates.

.. image:: images/pretty_json.png



