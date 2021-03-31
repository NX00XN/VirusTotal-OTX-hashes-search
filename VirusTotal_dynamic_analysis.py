import pprint
import requests
import json
import argparse


BASE_URL = 'https://www.virustotal.com/api/v3/'
API_KEY = 'XYZ' #Insert Here API key

# File behaviour reports
# '/files/{hash}/behaviours'
def get_file_behaviour_report(hash):
    url = 'files/' + hash + '/behaviours'
    headers = {'x-apikey': API_KEY}
    response = requests.get(BASE_URL + url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        response_json = response.json()
        error = response_json['error']['code'] + ' - ' + response_json['error']['message']
        return error

# main
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Add hash.')
    parser.add_argument('--file', help='foo help')
    args = parser.parse_args()

    behaviour_result = get_file_behaviour_report(args.file)

    print(json.dumps(behaviour_result)) #json parse
