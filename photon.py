#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Let's import what we need
import os
import sys
import time
import random
import warnings
import argparse
import threading
from re import search, findall
from requests import get, post, exceptions
from urllib.parse import urlparse # for python3

# EMAIL_REGEX = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
# PHONE_REGEX =


FILE_EXTENSIONS = [
    '.png',
    '.jpg',
    '.jpeg',
    '.js',
    '.css',
    '.pdf',
    '.ico',
    '.bmp',
    '.svg',
]
warnings.filterwarnings('ignore') # Disable SSL related warnings

end = red = white = green = yellow = run = bad = good = info = que = ''

def is_string_a_filename(string):
    for extension in FILE_EXTENSIONS:
        if extension in string:
            return True
    return False

def get_user_agent():
    return "Mozilla/5.0 (Macintosh; Intel Mac OS X {0}_{1}_{2}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36".format(random.randint(1, 10), random.randint(1, 15), random.randint(1, 20))

def crawl(main_inp, delay=0, timeout=5, crawl_level=2):
    ninja = True  # Ninja mode toggle
    thread_count = 16  # Number of threads

    # Variables we are gonna use later to store stuff
    intel = set() # emails, website accounts, aws buckets etc.
    custom = set() # string extracted by custom regex pattern
    failed = set() # urls that photon failed to crawl (NECESSARY)
    scripts = set() # javascript files
    external = set() # urls that don't belong to the target i.e. out-of-scope
    fuzzable = set() # urls that have get params in them e.g. example.com/page.php?id=2
    endpoints = set() # urls found from javascript files
    processed = set() # urls that have been crawled (NECESSARY)
    storage = set() # urls that belong to the target i.e. in-scope

    everything = []
    bad_intel = set() # unclean intel urls
    bad_scripts = set() # unclean javascript file urls

    # If the user hasn't supplied the root url with http(s), we will handle it
    if main_inp.startswith('http'):
        main_url = main_inp
    else:
        try:
            get('https://' + main_inp, timeout=timeout)
            main_url = 'https://' + main_inp
        except:
            main_url = 'http://' + main_inp

    storage.add(main_url) # adding the root url to storage for crawling

    domain_name = urlparse(main_url).netloc # Extracts domain out of the url

    ####
    # This function makes requests to webpage and returns response body
    ####

    with open(sys.path[0] + '/photon/core/user-agents.txt', 'r') as uas:
        user_agents = [agent.strip('\n') for agent in uas]

    def requester(url):
        processed.add(url) # mark the url as crawled
        time.sleep(delay) # pause/sleep the program for specified time
        def normal(url):
            headers = {
            'Host' : domain_name, # ummm this is the hostname?
            'User-Agent' : random.choice(user_agents), # selecting a random user-agent
            'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language' : 'en-US,en;q=0.5',
            'Accept-Encoding' : 'gzip',
            'DNT' : '1',
            'Connection' : 'close'}
            # make request and return response
            try:
                try:
                    response = get(url, headers=headers, verify=False, timeout=timeout, stream=True)
                except exceptions.ReadTimeout:
                    print("{} timedout".format(url))
                    return 'dummy'
                if 'text/html' in response.headers['content-type']:
                    if response.status_code != '404':
                        return response.text
                    else:
                        response.close()
                        failed.add(url)
                        return 'dummy'
                else:
                    response.close()
                    return 'dummy'
            except:
                return 'dummy'

        # pixlr.com API
        def pixlr(url):
            if url == main_url:
                url = main_url + '/' # because pixlr throws error if http://example.com is used
            # make request and return response
            try:
                response = get('https://pixlr.com/proxy/?url=' + url, timeout=timeout, headers={'Accept-Encoding' : 'gzip'}, verify=False)
                return response.text
            except exceptions.ReadTimeout:
                print("{} timedout".format(url))
            return 'dummy'

        # codebeautify.org API
        def code_beautify(url):
            headers = {
            'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0',
            'Accept' : 'text/plain, */*; q=0.01',
            'Accept-Encoding' : 'gzip',
            'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin' : 'https://codebeautify.org',
            'Connection' : 'close'
            }
            # make request and return response
            return post('https://codebeautify.com/URLService', headers=headers, data='path=' + url, verify=False).text

        # www.photopea.com API
        def photopea(url):
            # make request and return response
            try:
                response = get('https://www.photopea.com/mirror.php?url=' + url, timeout=timeout, verify=False)
                return response.text
            except exceptions.ReadTimeout:
                print("{} timedout".format(url))
            return 'dummy'

        if ninja: # if the ninja mode is enabled
            # select a random request function i.e. random API
            response = random.choice([photopea, normal, pixlr, code_beautify])(url)
            return response or 'dummy'
        else:
            return normal(url)

    ####
    # This function extracts links from robots.txt and sitemap.xml
    ####

    def zap(url):
        try:
            response = get(url + '/robots.txt', timeout=timeout).text # makes request to robots.txt
        except exceptions.ReadTimeout:
            print("{} timedout".format(url))
        if '<body' not in response: # making sure robots.txt isn't some fancy 404 page
            matches = findall(r'Allow: (.*)|Disallow: (.*)', response) # If you know it, you know it
            if matches:
                for match in matches: # iterating over the matches, match is a tuple here
                    match = ''.join(match) # one item in match will always be empty so will combine both items
                    if '*' not in match: # if the url doesn't use a wildcard
                        url = main_url + match
                        storage.add(url) # add the url to storage list for crawling
        response = get(url + '/sitemap.xml', timeout=timeout).text # makes request to sitemap.xml
        if '<body' not in response: # making sure robots.txt isn't some fancy 404 page
            matches = findall(r'<loc>[^<]*</loc>', response) # regex for extracting urls
            if matches: # if there are any matches
                print('%s URLs retrieved from sitemap.xml: %s' % (good, len(matches)))
                for match in matches:
                    storage.add(match.split('<loc>')[1][:-6]) #cleaning up the url & adding it to the storage list for crawling

    ####
    # This functions checks whether a url matches a regular expression
    ####

    def remove_regex(urls, regex):
        """
        Parses a list for non-matches to a regex

        Args:
            urls: iterable of urls
            custom_regex: string regex to be parsed for

        Returns:
            list of strings not matching regex
        """

        if not regex:
            return urls

        # to avoid iterating over the characters of a string
        if not isinstance(urls, (list, set, tuple)):
            urls = [urls]

        try:
            non_matching_urls = [url for url in urls if not search(regex, url)]
        except TypeError:
            return []

        return non_matching_urls


    ####
    # This functions checks whether a url should be crawled or not
    ####

    def is_link(url):
        # file extension that don't need to be crawled and are files
        return url not in processed and not is_string_a_filename(url)

    ####
    # This function extracts string based on regex pattern supplied by user
    ####

    supress_regex = False
    def regxy(pattern, response):
        try:
            matches = findall(r'%s' % pattern, response)
            for match in matches:
                custom.add(match)
        except:
            supress_regex = True

    ####
    # This function extracts intel from the response body
    ####

    def intel_extractor(response):
        matches = findall(r'''([\w\.-]+s[\w\.-]+\.amazonaws\.com)|([\w\.-]+@[\w\.-]+\.[\.\w]+)''', response)
        if matches:
            for match in matches: # iterate over the matches
                bad_intel.add(match) # add it to intel list
    ####
    # This function extracts js files from the response body
    ####

    def js_extractor(response):
        matches = findall(r'src=[\'"](.*?\.js)["\']', response) # extract .js files
        for match in matches: # iterate over the matches
            bad_scripts.add(match)

    ####
    # This function extracts stuff from the response body
    ####

    def extractor(url):
        response = requester(url) # make request to the url
        matches = findall(r'<[aA].*href=["\']{0,1}(.*?)["\']', response)
        for link in matches: # iterate over the matches
            link = link.split('#')[0] # remove everything after a "#" to deal with in-page anchors
            if is_link(link): # checks if the urls should be crawled
                if link[:4] == 'http':
                    if link.startswith(main_url):
                        storage.add(link)
                    else:
                        external.add(link)
                elif link[:2] == '//':
                    if link.split('/')[2].startswith(domain_name):
                        storage.add(link)
                    else:
                        external.add(link)
                elif link[:1] == '/':
                    storage.add(main_url + link)
                else:
                    storage.add(main_url + '/' + link)

        intel_extractor(response)
        js_extractor(response)
        # if args.regex and not supress_regex:
        #     regxy(args.regex, response)

    ####
    # This function extracts endpoints from JavaScript Code
    ####

    def jscanner(url):
        response = requester(url) # make request to the url
        matches = findall(r'[\'"](/.*?)[\'"]|[\'"](http.*?)[\'"]', response) # extract urls/endpoints
        for match in matches: # iterate over the matches, match is a tuple
            match = match[0] + match[1] # combining the items because one of them is always empty
            if not search(r'[}{><"\']', match) and not match == '/': # making sure it's not some js code
                endpoints.add(match) # add it to the endpoints list

    ####
    # This function starts multiple threads for a function
    ####

    def threader(function, *urls):
        threads = [] # list of threads
        urls = urls[0] # because urls is a tuple
        for url in urls: # iterating over urls
            task = threading.Thread(target=function, args=(url,))
            threads.append(task)
        # start threads
        for thread in threads:
            thread.start()
        # wait for all threads to complete their work
        for thread in threads:
            thread.join()
        # delete threads
        del threads[:]

    ####
    # This function processes the urls and sends them to "threader" function
    ####

    def flash(function, links): # This shit is NOT complicated, please enjoy
        links = list(links) # convert links (set) to list
        for begin in range(0, len(links), thread_count): # range with step
            end = begin + thread_count
            splitted = links[begin:end]
            threader(function, splitted)
            progress = end
            if progress > len(links): # fix if overflow
                progress = len(links)
            sys.stdout.write('\r%s Progress: %i/%i' % (info, progress, len(links)))
            sys.stdout.flush()
        print('')

    then = time.time() # records the time at which crawling started

    # Step 1. Extract urls from robots.txt & sitemap.xml
    zap(main_url)

    # this is so the level 1 emails are parsed as well
    storage = set(storage)

    # Step 2. Crawl recursively to the limit specified in "crawl_level"
    for level in range(crawl_level):
        links = storage - processed # links to crawl = all links - already crawled links
        if not links: # if links to crawl are 0 i.e. all links have been crawled
            break
        elif len(storage) <= len(processed): # if crawled links are somehow more than all links. Possible? ;/
            if len(storage) > 2: # if you know it, you know it
                break
        print('%s Level %i: %i URLs' % (run, level + 1, len(links)))
        try:
            flash(extractor, links)
        except KeyboardInterrupt:
            print('')
            break

    for match in bad_scripts:
        if match.startswith(main_url):
            scripts.add(match)
        elif match.startswith('/') and not match.startswith('//'):
            scripts.add(main_url + match)
        elif not match.startswith('http') and not match.startswith('//'):
            scripts.add(main_url + '/' + match)
    # Step 3. Scan the JavaScript files for enpoints
    print('%s Crawling %i JavaScript files' % (run, len(scripts)))
    flash(jscanner, scripts)

    for url in storage:
        if '=' in url:
            fuzzable.add(url)

    for match in bad_intel:
        for x in match: # because "match" is a tuple
            if x != '' and not is_string_a_filename(x): # if the value isn't empty
                intel.add(x)

    for url in external:
        if 'github.com' in url or 'facebook.com' in url or 'instagram.com' in url or 'youtube.com' in url or 'twitter.com' in url:
            intel.add(url)

    now = time.time() # records the time at which crawling stopped
    diff = (now - then) # finds total time taken

    def timer(diff):
        minutes, seconds = divmod(diff, 60) # Changes seconds into minutes and seconds
        try:
            time_per_request = diff / float(len(processed)) # Finds average time taken by requests
        except ZeroDivisionError:
            time_per_request = 0
        return minutes, seconds, time_per_request
    minutes, seconds, time_per_request = timer(diff)

    datasets = [intel, custom, failed, storage, scripts, external, fuzzable, endpoints]

    # Printing out results
    print('''
        %s URLs: %i
        %s Intel: %i
        %s JavaScript Files: %i
        ''' % (good, len(storage), good,len(intel), good, len(scripts))
    )

    print('%s Total time taken: %i minutes %i seconds' % (info, minutes, seconds))
    print('%s Average request time: %s seconds' % (info, time_per_request))
    return intel
