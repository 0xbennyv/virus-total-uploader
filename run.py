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


# User Input, Asking for files
def user_input():
    # Ask the mode to run
    mode = input("""What mode would you like to run in?
    1)  Batch mode 
    2)  Single file mode
    99) Exit
    Enter selection: """)

    # If mode is batch mode
    if mode == '1':
        path = input("Enter the directory to scan: ")
        # Check to make sure the path is valid and continue
        if os.path.isdir(path):
            print(f'[*] Directory {path} is valid')
            print('[*] Proceeding to check the hash against VirusTotal')
            # Batch mode function will check files and ignore those not needed.
            batch_mode(path)
            # If the file is not valid it'll then ask the question again
        else:
            # Error message
            print(f'[*] Directory {path} is NOT valid')
            # Restart the function
            print('[*] Please try again')
            user_input()

    # If mode is a single file
    elif mode == '2':
        file = input("[*] Enter the path of your file: ")
        # Check to make sure the path is valid and continue
        if os.path.isfile(file):
            print(f'[*] File {file} is valid')
            print('[*] Proceeding to Check the hash against VirusTotal')
            # Do a hash lookup of the file, if this fails it'll then upload the file
            scan = 'single'
            hash_lookup(file, scan)
            # If the file is not valid it'll then ask the question again
        else:
            # Error message
            print(f'[*] File {file} is NOT valid')
            # Restart the function
            print('[*] Please try again')
            user_input()

    # Exit cleanly
    elif mode == '99':
        print("At least tell me it's you, not me.")
        exit()
    else:
        user_input()


# Get each folder in the directory for batch mode
def batch_mode(path):
    for file in os.listdir(path):
        if not file.startswith('.'):
            if os.path.isfile(os.path.join(path, file)):
                file = os.path.abspath(file)
                scan_type = 'batch'
                hash_lookup(file, scan_type)


# Check file hash first
def hash_lookup(file, scan_type, mode='sha256'):
    # Set the mode for HashLib
    h = hashlib.new(mode)
    # Open the file to hash
    with open(file, 'rb') as file:
        # Set the block size so you don't kill yer memory
        block = file.read(512)
        # Start reading the file
        while block:
            h.update(block)
            block = file.read(512)
    # Hash the file
    file_hash = h.hexdigest()
    # Set the API Params
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key,
              'resource': file_hash}
    # Make the request
    response = requests.get(url, params=params)
    # Get the response in JSON
    json_response = response.json()
    # If the file hasn't been seen before it'll submit the file to VT
    if json_response['response_code'] == 0:
        if scan_type == 'single':
            print('[*] File not seen from VirusTotal before, going to submit')
            file_submission(file)
        if scan_type == 'batch':
            print('[*] File not seen before, skipping submission.')
            # Create and Write the results to CSV
            f = open("skipped_files.txt", "a")
            f.write(f'{file.name}, {file_hash} \n')
            f.close()
    # If the file has been seen it'll prep the report
    else:
        print('[*] File already scanned, getting data')
        # Send the data to be parsed and CSV'd
        parse_data(json_response)


# Upload the file to virus total
def file_submission(file):
    # Let the user know what's going on for uploading
    print('[*] Uploading to VirusTotal')
    # Set the API Params
    params = {'apikey': api_key}
    files = {'file': (file, open(file, 'rb'))}
    # Make the request happen
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    # Get the response in JSON
    json_response = response.json()
    # Send the data to be parsed and CSV'd
    parse_data(json_response)


# Prep the results to make a CSV here.
def parse_data(json_data):
    # Create the DICT that we'll convert to CSV
    csv_data = {}
    # Keys for the fields we want to include
    keys = ['sha256', 'scan_date', 'permalink', 'positives']
    # Check in the config file to see if a particular vendor is being reported on or if it's all the vendors
    if vendor == 'all':
        # Start looping through our keys for the file information
        for key in keys:
            # Make the initial dict with the file information
            csv_data.update({key: json_data[key]})
        # Start looping through the scan data for every vendor
        for vendors in json_data['scans']:
            csv_data.update({f'{vendors} detected': json_data['scans'][vendors]['detected'],
                             f'{vendors} result': json_data['scans'][vendors]['result'],
                             f'{vendors} update': json_data['scans'][vendors]['update'],
                             f'{vendors} version': json_data['scans'][vendors]['version']})
    else:
        # Fields we want to select from the scan data
        scan_keys = ['detected', 'result', 'update', 'version']
        # Start looping through the keys for the file information
        for key in keys:
            # Make the initial dict with the file information
            csv_data.update({key: json_data[key]})
        # Start looping through the scan data for just the vendor chosen
        for scan_key in scan_keys:
            csv_data.update({'Vendor': vendor})
            csv_data.update({scan_key: json_data['scans'][vendor][scan_key]})
    # Create and Write the results to CSV
    with open(f'{vendor}_scan_result.csv', 'w') as f:
         w = csv.DictWriter(f, csv_data.keys())
         w.writeheader()
         w.writerow(csv_data)


# Let's rock the casbah!
if __name__ == "__main__":
    # Star the initial user requests
    user_input()