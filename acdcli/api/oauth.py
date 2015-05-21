import os
import json
import requests
import time
import logging
import urllib
import datetime
import sys

__all__ = ['init', 'get_auth_header', 'get_auth_header_curl']

logger = logging.getLogger(__name__)

cache_path = ''
OAUTH_DATA_FILE = 'oauth_data'
CLIENT_INFO_FILE = 'client_info'

# json key names
EXP_IN_KEY = 'expires_in'
ACC_TOKEN_KEY = 'access_token'
REFR_TOKEN_KEY = 'refresh_token'

EXP_TIME_KEY = 'exp_time'

oauth_data_path = lambda: os.path.join(cache_path, OAUTH_DATA_FILE)
client_info_path = lambda: os.path.join(cache_path, CLIENT_INFO_FILE)
oauth_data = {}

# Here are amazon steps to get access token:
# 1. Redirect customer to Login with Amazon and obtain code
# 2. Your service leverages the code returned to ask for an access_token
# 3. Use refresh_token to obtain new access_token when expired

#client info:
client_info = {'client_id': '',
               'client_secret': ''}
# remote request URLs
CODE_URL = 'https://www.amazon.com/ap/oa?'
TOKEN_URL = 'https://api.amazon.com/auth/o2/token'
TOKEN_HEADER = {'Content-Type': 'application/x-www-form-urlencoded'}

def _oauth_data_changed():
    with open(oauth_data_path(), 'w') as oa:
        json.dump(oauth_data, oa, indent=4, sort_keys=True)

def init(path: str) -> bool:
    global cache_path
    cache_path = path

    try:
        _get_data()
        return True
    except:
        raise

def _read_client_app_info():
    global client_info
    print('Client info file: %s' % client_info_path())
    if not os.path.isfile(client_info_path()):
        amazon_client_id = input('Please input amazon Client id: ')
        amazon_client_secret = input('Please input Amazon Client Secret:')
        client_info['client_id'] = amazon_client_id
        client_info['client_secret'] = amazon_client_secret
        ci = open(client_info_path(), 'w')
        json.dump(client_info, ci, indent=4, sort_keys=True)
        ci.close()
    else:
        ci = open(client_info_path())
        client_info = json.load(ci)
        ci.close()

def _init_auth_data():
    global oauth_data
    global client_info
    # read client info
    _read_client_app_info()

    # 1. Redirect customer to Login with Amazon and obtain code
    CODE_PARAM = { 'scope': 'clouddrive:read clouddrive:write',
              'response_type': 'code',
              'client_id': client_info['client_id'],
              'redirect_uri': 'http://localhost/'}
    print('\nPlease open the following link in your browser,\n'
          'and click "Continue"(or login your amazon account) to get the auth code:')
    print(CODE_URL + urllib.parse.urlencode(CODE_PARAM))

    print('\n\nThen, you will get an URL in browser\'s address bar.\n'
          'Like this: http://localhost/?code=ANUSisdffsdfssdfsfsGD&scope=clouddrive%3Aread+clouddrive%3Awrite')
    auth_code_url = input('Please copy whole URL and input here:\n')
    auth_parm_list = urllib.parse.urlparse(auth_code_url).query.split('&')
    auth_code=''
    for auth_parm in auth_parm_list:
        if auth_parm is not None and auth_parm.startswith('code'):
            auth_code = auth_parm.strip('code=')

    logger.info('Auth code is %s' % auth_code)

    # 2. Your service leverages the code returned to ask for an access_token
    request_body = {'grant_type': 'authorization_code',
                  'code': auth_code,
                  'client_id': client_info['client_id'],
                  'client_secret': client_info['client_secret'],
                  'redirect_uri': 'http://localhost/'}

    response = requests.post(TOKEN_URL, headers=TOKEN_HEADER, data=request_body)
    if response.status_code is not 200:
        logger.critical('Refresh error, response code: ' + str(response.status_code))
        logger.critical('Error Msg: ' + str(response.json()))
        raise Exception

    oauth_data = response.json()
#    save to oauth file
    t = time.time()
    _treat_auth_token(oauth_data, t)
    _oauth_data_changed()

def _get_data():
    global oauth_data

    curr_time = time.time()

    if not os.path.isfile(oauth_data_path()):
        _init_auth_data()

        if not os.path.isfile(oauth_data_path()):
            logger.error('File "%s" not found.' % OAUTH_DATA_FILE)
            raise Exception

    with open(oauth_data_path()) as oa:
        oauth_data = json.load(oa)
        if EXP_TIME_KEY not in oauth_data:
            _treat_auth_token(oauth_data, curr_time)
            _oauth_data_changed()


def _get_auth_token() -> str:
    global oauth_data
    if time.time() > oauth_data[EXP_TIME_KEY]:
        logger.info('Token expired at %s.' % datetime.datetime.fromtimestamp(oauth_data[EXP_TIME_KEY]).isoformat(' '))

        # if multiple instances are running, check for updated file
        with open(oauth_data_path()) as oa:
            oauth_data = json.load(oa)

        if time.time() > oauth_data[EXP_TIME_KEY]:
            _refresh_auth_token()
        else:
            logger.info('Externally updated token found in oauth file.')
    return "Bearer " + oauth_data[ACC_TOKEN_KEY]


def get_auth_header() -> dict:
    return {'Authorization': _get_auth_token()}


def get_auth_header_curl() -> list:
    return ['Authorization: ' + _get_auth_token()]


def _treat_auth_token(token: str, curr_time: float):
    """Adds expiration time to Amazon OAuth dict"""
    if not token:
        return
    try:
        token[EXP_TIME_KEY] = curr_time + token[EXP_IN_KEY] - 120
        logger.info('New token expires at %s.' % datetime.datetime.fromtimestamp(token[EXP_TIME_KEY]).isoformat(' '))
    except KeyError as e:
        logger.critical('Fatal error: Token key "%s" not found.' % EXP_IN_KEY)
        raise e


def _refresh_auth_token():
    global oauth_data

    logger.info('Refreshing authentication token.')
    _read_client_app_info()

    t = time.time()

    request_body = {'grant_type': 'refresh_token',
                  'refresh_token': oauth_data[REFR_TOKEN_KEY],
                  'client_id': client_info['client_id'],
                  'client_secret': client_info['client_secret']}

    response = requests.post(TOKEN_URL, headers=TOKEN_HEADER, data=request_body)
    if response.status_code is not 200:
        logger.critical('Refresh error: Invalid code: ' + str(response.status_code))
        logger.critical('Error Msg: ' + str(response.json()))
        raise Exception

    try:
        r = response.json()
    except ValueError as e:
        logger.critical('Refresh error: Invalid JSON.')
        raise e

    _treat_auth_token(r, t)
    oauth_data = r
    _oauth_data_changed()
