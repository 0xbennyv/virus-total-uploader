import requests
import os
import csv
import hashlib
import configparser

# Import settings from configuration file
config = configparser.ConfigParser()
config.read('config.ini')
api_key = config['virustotal']['api']
vendor = config['virustotal']['vendor']


# Print Pretty JSON
def parse_data(json_data):
    # print(json.dumps(json_data, sort_keys=True, indent=4))
    # scan_data = [json_data['sha256'], json_data['scan_date'], json_data['permalink'], json_data['positives'],
    #              json_data['scans']['Sophos']['detected'], json_data['scans']['Sophos']['result'],
    #              json_data['scans']['Sophos']['update'], json_data['scans']['Sophos']['version']]
    csv_data = {}
    if vendor == 'all':
        keys = ['sha256', 'scan_date', 'permalink', 'positives', 'scans']
        scan_keys = ['detected', 'result', 'update', 'version']
        for key in keys:
            csv_data.update({key: json_data[key]})
        for vendors in json_data['scans']:
            csv_data.update({f'{vendors} detected': json_data['scans'][vendors]['detected'],
                             f'{vendors} result': json_data['scans'][vendors]['result'],
                             f'{vendors} update': json_data['scans'][vendors]['update'],
                             f'{vendors} version': json_data['scans'][vendors]['version']})
    else:
        keys = ['sha256', 'scan_date', 'permalink', 'positives']
        scan_keys = ['detected', 'result', 'update', 'version']
        for key in keys:
            csv_data.update({key: json_data[key]})
        for scan_key in scan_keys:
            csv_data.update({'Vendor': vendor})
            csv_data.update({scan_key: json_data['scans'][vendor][scan_key]})

    with open(f'{vendor}_scan_result.csv', 'w') as f:
         w = csv.DictWriter(f, csv_data.keys())
         w.writeheader()
         w.writerow(csv_data)


# User Input, Asking for files
def user_input():
    file = input("Enter the path of your file: ")
    if os.path.isfile(file):
        print(f'[*] File {file} is valid')
        print('[*] Proceeding to Check the hash against VirusTotal')
        hash_lookup(file)
    else:
        print(f'[*] File {file} is NOT valid')
        print('[*] Please try again')
        user_input()


# Check file hash first
def hash_lookup(file, mode='sha256'):
    h = hashlib.new(mode)
    with open(file, 'rb') as file:
        block = file.read(512)
        while block:
            h.update(block)
            block = file.read(512)
    file_hash = h.hexdigest()
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key,
              'resource': file_hash}
    response = requests.get(url, params=params)
    json_response = response.json()
    if json_response['response_code'] == 0:
        print('[*] File not seen from VirusTotal before, going to submit')
        file_submission(file)
    else:
        print('[*] File already scanned, getting data')
        parse_data(json_response)


# Upload the file to virus total
def file_submission(file):
    print('[*] Uploading to VirusTotal')
    params = {'apikey': api_key}
    files = {'file': (file, open(file, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    json_response = response.json()
    parse_data(json_response)


# Let's rock the casbah!
if __name__ == "__main__":
    user_input()