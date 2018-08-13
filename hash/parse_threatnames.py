####!/usr/bin/env python3
"""
reads the html AV sigs from a daily content release and parses to output text list of threatnames
threatnames to be used in pan-tort-plus search to get tags, filetypes, and other data from AF
"""

from bs4 import BeautifulSoup


def main():

    # counters if needed
    thid = 0
    sigcount = 0

    infile = 'AV_updates/AntiVirusExternal-2698.html'
    infileshort = 'AntiVirusExternal-2698'

    # Output file
    outfile = f'threatnames_{infileshort}.txt'

    with open(outfile, 'w') as threatfile:
            print(f'creating clean output file {outfile}')

    with open(f'{outfile}_quotes', 'w') as threatfile:
            print('cleaning GUI ready input file')

    # Open input file and get html input
    with open(infile, "r") as f:
        soup = BeautifulSoup(f, "html.parser")

    print(f'file {infile} opened.  Processing....')
    tbl1 = soup.find('table')

    threatnames = {}

    # iterate across tr table rows
    # NOTE: html has dupe <tr> so pushing to dict and hide dupes
    # sigprime is the prefix of the signame; has .abc suffixes added as sig variants
    for row in tbl1.findChildren('tr'):
        thid += 1
        cols = row.findChildren('td')
        sigprime = cols[0].text

        tmplist = []

        # iterate across the 2nd <td> which is variant suffixes
        # creates a list of threatname put into dict with key as the sigprime prefix
        for item in cols[1].text.split()[2:]:
            threatname = f'{sigprime}.{item}'.rstrip(",")
            tmplist.append(threatname)

        threatnames[sigprime] = tmplist

    # open output file and iterate through the dict-lists writing threatnames to file
    with open(outfile, 'a') as threatfile:
        for sigprime in threatnames:
            for threatname in threatnames[sigprime]:
                threatfile.write(f'{threatname}\n')
                sigcount += 1


    print("Number of Primary Signatures =", thid)
    print("Total number of sig variants: ", sigcount)

if __name__ == '__main__':
    main()