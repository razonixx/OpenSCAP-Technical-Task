import argparse
import os
import sys
import subprocess
import json
import socket

from time import gmtime, strftime
from bs4 import BeautifulSoup

args = None
result_folder = '/root/scans/'

def parseCommandLine():
    global args
    parser = argparse.ArgumentParser(description='Command line tool to execute OpenSCAP scans of the Oracle Linux 7 system using the "stig" profile from the "scap-security-guide" package')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--scan', action='store_true', help='start a new scan')
    group.add_argument('--history', action='store_true', help='list past scans')
    group.add_argument('--scan-id', help='show results of scan with a certain id')
    group.add_argument('--compare', nargs=2, help='compare 2 scans by id')

    if(len(sys.argv) == 1):
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()

def parseResult(rule_result_tag):
    result = {}
    result['id'] = rule_result_tag.get('idref')
    result['severity'] = rule_result_tag.get('severity')
    result['result'] = rule_result_tag.result.text
    return result

def scanReport(xmlFile):
    rule_result = []
    pass_count = 0
    fail_count = 0

    with open(xmlFile, 'r') as file:
        soup = BeautifulSoup(file, 'xml')

    test_target = soup.find('TestResult').target.text
    test_time = soup.find('TestResult').get('end-time')

    for rule_result_tag in soup.find_all('rule-result'):
        result = rule_result_tag.result.text
        if(result == 'notselected' or result == 'notapplicable'):
            continue
        rule_result.append(parseResult(rule_result_tag))
        if result == 'pass':
            pass_count+=1
        elif result == 'fail':
            fail_count+=1
    
    with open(result_folder+test_target+'_'+test_time+'.json', 'w') as file:
        json.dump(rule_result, file)

    for i in range(len(rule_result)):
        print('Id: {}\nSeverity: {}\nResult: {}\n'.format(rule_result[i]['id'], rule_result[i]['severity'], rule_result[i]['result']))
    
    print('Test Target: {}\nUTC Time: {}\nTotal tests: {}\nPassed: {}\nFailed: {}\nNot Executed: {}'.format(test_target, test_time, len(rule_result), pass_count, fail_count, len(rule_result)-pass_count-fail_count))

def getFilenameById(fileID):
    files = os.listdir(result_folder)
    id = 1

    for file in sorted(files):
        if(int(fileID) == id):
            return file
        id+=1

def compareReports(id_1, id_2):
    fixed_issues = []
    new_issues = []

    file_1 = getFilenameById(id_1)
    file_2 = getFilenameById(id_2)

    file_1_pass_count = 0
    file_1_fail_count = 0
    file_2_pass_count = 0
    file_2_fail_count = 0

    with open(result_folder + file_1, 'r') as file:
        rule_result_1 = json.load(file)

    with open(result_folder + file_2, 'r') as file:
        rule_result_2 = json.load(file)

    for i in range(len(rule_result_1)):
        if rule_result_1[i]['result'] == 'pass' and rule_result_2[i]['result'] == 'fail':
            new_issues.append(rule_result_2[i])
        elif rule_result_1[i]['result'] == 'fail' and rule_result_2[i]['result'] == 'pass':
            fixed_issues.append(rule_result_2[i])

    for i in range(len(rule_result_1)):
        if rule_result_1[i]['result'] == 'pass':
            file_1_pass_count+=1
        elif rule_result_1[i]['result'] == 'fail':
            file_1_fail_count+=1

    for i in range(len(rule_result_2)):
        if rule_result_2[i]['result'] == 'pass':
            file_2_pass_count+=1
        elif rule_result_2[i]['result'] == 'fail':
            file_2_fail_count+=1

    print('First scan summary statistics\nHost: {}\nDate: {}\nTotal: {}\nPassed: {}\nFailed: {}\nNotExecuted: {}\n'.format(file_1[:-25], file_1[-24:-5], len(rule_result_1), file_1_pass_count, file_1_fail_count, len(rule_result_1) - file_1_pass_count - file_1_fail_count))
    print('Second scan summary statistics\nHost: {}\nDate: {}\nTotal: {}\nPassed: {}\nFailed: {}\nNot Executed: {}\n'.format(file_2[:-25], file_2[-24:-5], len(rule_result_2), file_2_pass_count, file_2_fail_count, len(rule_result_2) - file_2_pass_count - file_2_fail_count))
    
    if fixed_issues:
        print('Fixes in second scan')
        for rule in fixed_issues:
            print('Id: {}\tSeverity: {}\n'.format(rule['id'], rule['severity']))

    if new_issues:
        print('New issues in second scan')
        for rule in new_issues:
            print('Id: {}\tSeverity: {}\n'.format(rule['id'], rule['severity']))

    if not fixed_issues and not new_issues:
        print('No changes were detected')

def showScanHistory():
    files = os.listdir(result_folder)
    id = 1

    print("Scan history: ")
    for file in sorted(files):
        print('ID: {} Filename: {}'.format(id, file))
        id+=1
    if id == 1:
        print('No scans found')

def getReportById(fileID):
    pass_count = 0
    fail_count = 0
    filename = getFilenameById(fileID)

    with open(result_folder + filename, 'r') as file:
        rule_result = json.load(file)

    for i in range(len(rule_result)):
        if rule_result[i]['result'] == 'pass':
            pass_count+=1
        elif rule_result[i]['result'] == 'fail':
            fail_count+=1
        print('Id: {}\nSeverity: {}\nResult: {}\n'.format(rule_result[i]['id'], rule_result[i]['severity'], rule_result[i]['result']))
    
    print('Test Target: {}\nUTC Time: {}\nTotal tests: {}\nPassed: {}\nFailed: {}\nNot Executed: {}'.format(filename[:-25], filename[-24:-5], len(rule_result), pass_count, fail_count, len(rule_result) - pass_count - fail_count))

parseCommandLine()
if args.scan:
    hostname = socket.gethostname()
    date = strftime("%Y-%m-%dT%H:%M:%S", gmtime())
    subprocess.run([
        'oscap',
        'xccdf', 
        'eval', 
        '--profile', 
        'stig', 
        '--results', 
        '/root/openscap/results/'+hostname+'_'+date+'.xml',
        '--cpe',
        '/usr/share/xml/scap/ssg/content/ssg-ol7-cpe-dictionary.xml',
        '/usr/share/xml/scap/ssg/content/ssg-ol7-xccdf.xml'
    ])
    scanReport('/root/openscap/results/'+hostname+'_'+date+'.xml')

if args.scan_id:
    getReportById(args.scan_id)

if args.compare:
    compareReports(args.compare[0], args.compare[1])
    
if args.history:
    showScanHistory()