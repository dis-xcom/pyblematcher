#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import tarfile
import urllib2
import yaml
import hashlib

def walklogs(topdir):
    for dirName, subdirList, fileList in os.walk(topdir):
        for filename in fileList:
            path = '{0}/{1}'.format(dirName,filename)
            yield (path)


def readlines(logfile):
    with open(logfile) as log:

        found = 0 # 0 - traceback not found, 1 - found traceback, 2 - found comment of exception.
        res = {'trace': [], 'filename':logfile}
        i = 0
        for l in log.readlines():
            if found and len(l) > i:
                if 'Traceback' in l:
                    yield (res)
                    i = l.find('Traceback')
                    res['trace'] = [l[i:]]
                    found = 1
                elif found == 1:
                    if l[i:i+2] == '  ':
                        res['trace'].append(l[i:])
                    else:
                        if l[i].isupper():
                            found = 2
                            res['trace'].append(l[i:])
                        else:
                            found = 0
                            i = 0
                            yield (res)
                elif found == 2:
                    if l[i].isupper():
                        res['trace'].append(l[i:])
                    else:
                        found = 0
                        i = 0
                        yield (res)
            else:
                if 'Traceback' in l:
                    i = l.find('Traceback')
                    found = 1
                    res['trace'].append(l[i:])
                else:
                    found = 0
                    i = 0
        if res:
            yield (res)

def scanlogs(topdir):
    logfiles = walklogs(topdir)
    for logfile in logfiles:
        blocks = readlines(logfile)
        for block in blocks:
            yield (block)

def scan_tracebacks(path):
    print ("="*100)
    tracebacks = scanlogs(path)
    tracebacks_count = 0

    for traceback in tracebacks:
        if traceback['trace']:
            tracebacks_count += 1
            continue
            print ("[ " + traceback['filename'] + " ]")
            for line in traceback['trace']:
              if line and line[0] != ' ' and 'Traceback' not in line:
                print line.rstrip()

    print("Tracebacks count: {}".format(tracebacks_count))


#scan_tracebacks('.')

def yaml_read(yaml_file):
    if os.path.isfile(yaml_file):
        with open(yaml_file, 'r') as f:
            return yaml.load(f)
    else:
        print("\'{}\' is not a file!".format(yaml_file))

class Template(object):

    def __init__(self, template):
        self.name = template['name']
        self.roles = template['roles']
        self.query = template['query']

    def striptime(self, line):
        results = re.search("""
            ^(?:.{,20})          # Time should begin no farther then 20 chars from start of the line
            (\d{4}-\d{2}-\d{2})  # date
            .                    # any single separator
            (\d{2}:\d{2}:\d{2})  # time
            (?:\S|\d+)*          # suffix (milliseconds, etc)
            \s+                  # space separator
            (.*)                 # the rest of the string
            """,
                            line, re.VERBOSE)

        if results:
            time = (results.group(1), results.group(2))
            return (time, results.group(3))
        else:
            return (None, line)

    def print_properties(self):
        print("==== Template name: {}".format(self.name))
        print("             roles: {}".format(self.roles))
        for x in range(len(self.query)):
            print("             query: {}".format(self.query[x]))

    def find_string(self, str_value):
        """ Find index of query string by value """
        for i, query in enumerate(self.query):
            if str_value == query['string']:
                return i

    def results_hash(self, res):
        res_hash=hashlib.md5()
        for x in res['strings']:
            for r in x['results']:
                res_hash.update(x['results'][r].encode('utf-8'))
        res['res_hash'] = res_hash.hexdigest()

    def store(self, res, time, line, line_num, cur_str):
         results = {}
         for s in self.query[cur_str]['store']:
             if res['groups'][s]:
                 results[s] = res['groups'][s]
         res['strings'].append({
             'time': time,
             'results': results,
             'line': line,
             'line_num': line_num,
             'cur_query': self.query[cur_str],
             })


    def search(self, lines, logfile):
        """ lines - iterator of lines in opened file """
        res = {'groups':{}, 'strings': [], 'logfile': logfile}
# name: name of the template that found the result
# groups: {} #results of searching for groups
# logfile:  # log file name where the pattern was found
# res_hash: # hash of all [strings][results]
# strings: [ # ordered dicts for each found string:
#      {
#       'time': time               # time from line, or None
#       'results': {result.group()} # found patterns name:res
#       'line': line               # original line
#       'line_num': int            # original line position in log
#       'cur_query': query that was used for search the result
#      }
#    ]
        cur_str = 0
        for line_num, line in enumerate(lines):
#            if 'Traceback' in line:
#                print (" %%%%%%%%%% Found {}".format(line))
            if not line.strip():
                # Ignore empty lines
                continue

            if 'skip_keyword' in self.query[cur_str]:
                skip_keyword = self.query[cur_str]['skip_keyword']
#                print (" ######## {}".format(skip_keyword))
                if skip_keyword in line:
#                    print (" ######## SKIPPING LINE: {}".format(line))
                    continue

            time, l = self.striptime(line)
            if 'repeat_string_if_matches' in self.query[cur_str]:
                rep_str = self.find_string(self.query[cur_str]['repeat_string_if_matches'])
                if not rep_str:
                    print("########## INDEX ERROR IN {} ############".format(self.query[cur_str]))
                if self.scan_line(l[:2048], res['groups'], self.query[rep_str]):
                    self.store(res, time, line, line_num, rep_str)
                    cur_str = rep_str +1
                    continue
                elif cur_str == len(self.query):
                    # all strings that were collected
#                    print("@@@@@@@@ STORE TRACEBACK @@@@@@@@@")
                    self.results_hash(res)
                    yield res
                    cur_str = 0;
                    res = {'groups':{}, 'strings': [], 'logfile': logfile}

            if self.scan_line(l[:2048], res['groups'], self.query[cur_str]):
                self.store(res, time, line, line_num, cur_str)
                cur_str += 1
            elif cur_str:
                # Pattern doesn't match. Re-set all variables
                cur_str = 0;
                res = {'groups':{}, 'strings': [], 'logfile': logfile}
            if cur_str == len(self.query):
                # all strings that were collected
#                print("@@@@@@@@ STORE TRACEBACK @@@@@@@@@")
                self.results_hash(res)
                yield res
                cur_str = 0;
                res = {'groups':{}, 'strings': [], 'logfile': logfile}



#if repeat_string_if_matches - проверяем сначала попадание там

#else: ищем текущую строку
#            self.scan_line(l.strip(), res['groups'], self.query[cur_str])

#            if l.strip():
#                print l.strip()
#            if time:
#                print time

    def scan_line(self, line, res_groups, cur_query):
        # Quick pre-check if a keyword in line, before regexp it
        if 'fast_keyword' in cur_query:
            if cur_query['fast_keyword'] not in line:
                return

        re_str='^'
        for r in cur_query['groups']:
            if type(r) == type(dict()):
                g = r.keys()[0]
                s = r[g]
#                print("SSS {} {}".format(g, s))
            elif r in res_groups:
                g = r
                s = re.escape(res_groups[r])
            else:
                print("Unknown key:{}".format(r))
            re_str += "(?P<{0}>{1})".format(g, s)

        res = re.search(re_str, line)

        if not res:
            # Try to skip additional prefixes
            re_str='^'
            for r in cur_query['groups']:
                if type(r) == type(dict()):
                    g = r.keys()[0]
                    s = r[g]
                    re_str += "(?P<{0}>{1})".format(g, s)
            res = re.search(re_str, line)

        if res:
#            print re_str, line
#            print(" === Pattern found, query: {}".format(cur_query['groups']))
            # storing all keys
            for r in cur_query['groups']:
                if type(r) == type(dict()):
                    g = r.keys()[0]
                    s = r[g]
                    # search for exact match in found group
#                    print("### {} SEARCH {} IN '{}'".format(g, s, res.group(g)))

                    res1 = re.search(s, res.group(g))
                    res_groups[g] = ''.join(res1.groups())
#                    print("******* ADDING NEW KEY: {} {}".format(g, res_groups[g]))
            return True
#        print re_str

class Distiller(object):

    readlines = None
    fobj = None

    def __init__(self, fobj, fname):
        wrappers = {'/lastlog': self.fake_parser,
                    '/atop.log': self.fake_parser,
                    '/atop_': self.fake_parser,
                    '/atop_current': self.fake_parser,
                    '/supervisord.log': self.docker_parser,
                   }
        for w in wrappers.keys():
#            if fname.endswith(w):
            if w in fname:
                self.fobj = fobj
                self.readlines = wrappers[w]
                return
        self.readlines = fobj.readlines

    def fake_parser(self):
        yield ''

    def docker_parser(self):
        yield ''
#        for l in self.fobj.readlines():
#            yield l


yaml_file='./traceback.yaml'
t = yaml_read(yaml_file)
#print t
for template in t['templates']:
    tobj = Template(template)
#    tobj.print_properties()
#    tobj.striptime("2015-03-20T02:37:20.590877+00:00 notice: nailgun-agent:  I, [2015-03-20T02:37:20.567120 #1730]  INFO -- : MCollective is up to date with identity = 3")
#    tobj.striptime("[2015-03-20T02:37:20] notice: nailgun-agent:  I, [2015-03-20T02:37:20.567120 #1730]  INFO -- : MCollective is up to date with identity = 3")
#    tobj.striptime("2015-03-20 02:37:20.590877+00:00 notice: nailgun-agent:  I, [2015-0320T02:3720.567120 #1730]  INFO -- : MCollective is up to date with identity = 3")
    results = []

    logfiles = walklogs('./snapshots')
    for logfile in logfiles:
#        print("######## FILE: {}".format(logfile))
        with open(logfile) as log:
            fobj = Distiller(log, logfile)
#            for l in fobj.readlines():
#                print l
#            res = [x for x in tobj.search(log.readlines(), logfile)]
            res = [x for x in tobj.search(fobj.readlines(), logfile)]
            if res:
                results.extend(res)

    print("####### TOTAL yaml FOUND: {}", format(len(results)))
    for n, r in enumerate(results):
        print ("'{}' - 'logfile': {} , {}".format(n, r['logfile'], r['strings'][0]['line_num']))
        print ("'{}' - 'res_hash': {}".format(n, r['res_hash']))
        for s in r['strings']:
            print ("'{}' - {}".format(n, s['results']))


#    log_file='./snapshots/fuel-snapshot-2015-03-20_09-36-37/10.109.0.2/var/log/docker-logs/remote/node-2.test.domain.local/ceilometer-agent-notification.log'
#    log_file='./snapshots/fuel-snapshot-2015-03-20_04-37-48/10.109.0.2/var/log/docker-ostf.log'
#    log_file='./fuel-snapshot-2015-03-20_04-02-58/10.109.40.2/var/log/docker-logs/ostf-stdout.log'
#    log_file='./fuel-snapshot-2015-03-20_04-02-58/10.109.40.2/var/log/docker-logs/astute/astute.log'
#    with open(log_file) as log:
#        res = [x for x in tobj.search(log.readlines())]

#    for n, r in enumerate(res):
##        print("{}".format(r['strings']))
#        for s in r['strings']:
#            print ("'{}' - {}".format(n, s['results']))


