Prerequisites and Installation
==============================

These instructions are for a stand-alone install from github to run locally.

Prerequisites
-------------

The following requirements must be met before installing and using pan-tort.


Autofocus API Key
~~~~~~~~~~~~~~~~~

Ensure you have an active Autofocus subscription and API key.

`Get your Autofocus API key`_

.. _Get your Autofocus API key: https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_api/get-started-with-the-autofocus-api/get-your-api-key

This key will be used below after pan-tort is installed.

Python, virtual environment, and pip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The code in pan-tort requires python 3.6 or later. The examples will use python 3.6.

The examples also show python running in a virtual environment with pip used to install required packages.

`Python 3.6 virtual environment documentation`_

.. _Python 3.6 virtual environment documentation: https://docs.python.org/3.6/tutorial/venv.html


In most cases pip is already installed if using python 3.6 or later.

Checking the pip version:

.. highlight:: bash

::

    $ pip --version
    pip 18.0 from /Users/localuser/pan-tort/env/lib/python3.6/site-packages/pip (python 3.6)


`pip information and installating instructions`_

.. _pip information and installating instructions: https://pip.pypa.io/en/stable/installing/


Once these requirements are met you are ready to install pan-tort.

Installation
------------

The initial steps are an overview to clone the repo and activate a python virtual environment.

::

    $ git clone git@github.com:PaloAltoNetworks/pan-tort.git
    $ cd pan-tort
    $ python3.6 -m venv env
    $ source env/bin/activate
    (env)$ pip install -r requirements.txt

The virtual environment name is ``env`` and if active will likely be shown to the left of the command prompt.
If successful, the pan-tort utility is installed and almost ready to use.


Autofocus API key
~~~~~~~~~~~~~~~~~

Once you have the api key, it will be used to create the af_api.py key file in the hash directory.
Any text editor can be used to create this file.

::

    api_key = '{your api key  goes here}'


Save the file as hash/af_api.py.


The hash_list.txt file
~~~~~~~~~~~~~~~~~~~~~~

This is the list of hashes used for the pan-tort query. There is no limit to the file size. Pan-tort will segment
the list automatically if more than 1,000 hashes are to be searched.

The hash file is a simple text file with one hash per line.
A sample hash file to edit is in the hash directory. These are md5 hashes.


Editting conf.py
~~~~~~~~~~~~~~~~

The conf.py file has default values for variables used in pan-tort.
One value that may need to be edited is the hashtype variable.
Make sure this value matches the hash type of the samples in the hash list.


::

    hashtype = 'md5'



Get the latest Autofocus malware tag data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The output data as context specific to malware family tags. To get the latest list required for pan tort,
run the gettagdata.py file in the hash directory.

::

    $ python gettagdata.py

This will take less than a minute and the output will be tagdata.json in the hash directory.

Run this utility periodically to ensure pan-tort has the latest tag data.









