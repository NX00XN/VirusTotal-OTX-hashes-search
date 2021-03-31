import pprint
import requests
import json
import argparse

BASE_URL = 'https://otx.alienvault.com:443/api/v1/'
API_KEY = 'XYZ' #Insert here API KEY


# '/indicators/file/{file_hash}/{section}'
def get_file_info(hash):
    url = '/indicators/file/'
    section = 'analysis'
    headers = {
        'accept': 'application/json',
        'X-OTX-API-KEY': API_KEY,
    }
    response = requests.get(BASE_URL + url + hash + '/' + section, headers=headers)

    if response.status_code == 200:
        if response.json()['analysis'] is not None:
            return response.json()
        else:
            return 'not_found'
    elif response.status_code == 404:
        return 'not_found'
    else:
        return 'error'

#  main
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Add hash.')
    parser.add_argument('--file', help='foo help')
    args = parser.parse_args()

    result = get_file_info(args.file)
    print(json.dumps(result)) #json print
