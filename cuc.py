import requests
from requests.auth import HTTPBasicAuth
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from xml.etree import ElementTree as ET
from random import randint
import json
import logging
import keyring
from servercheck import server_check
import sys

# Import logging setting from main function
logger = logging.getLogger(__name__)

# FUNCTION - Perform all CUC changes; Receive userid from calling mondule
def rest_call(userid_name):
    sys.stderr = open('cuc-rest-call-stderr.log', 'w')
    sys.stdout = open('cuc-rest-call-stdout.log', 'w')
    # ek - 07-04-19 - issue loging message to see how polling works
    print("STARTINGA")
    logger.info('CUC_REST_CALL STARTING-A')
    print("STARTINGB")

    disable_warnings(InsecureRequestWarning)
    # ek - 07-04-19 - issue loging message to see how polling works
    logger.info('CUC_REST_CALL STARTING-B')

    # Read in CUC settings from JSON file
    settings_file = 'userremoval.json'
    with open(settings_file) as data_file:
        settings_json = json.load(data_file)
        cuc_pub = settings_json['cuc_pub']
        cuc_user = settings_json['cuc_user']
        cuc_pw = keyring.get_password("CUC",cuc_user)
        pin_length = settings_json['pin_length']

    server_status = server_check(cuc_pub)
    # ek - 07-04-19 - issue loging message to see how polling works
    logger.info('CUC_REST_CALL AFTER SERVER CHECK')
    # If CUC server defined in JSON file is reachable
    if server_status:
        # Query for CUC userid
        user_url = 'https://%s/vmrest/users?query=(alias is %s)' % (cuc_pub, userid_name)
        # Attempt to query CUC user
        try:
            user_call = requests.get(user_url, auth=HTTPBasicAuth(cuc_user, cuc_pw), verify=False)
        # If no CUC servers reachable, return to main module
        except:
            logger.error('CUC REST access error connecting to %s' % (user_url))
            return
        # If valid CUC server is reachable
        else:
            if user_call.status_code == 401:
                logger.error('Invalid credentials for CUC at %s' % (cuc_pub))
                return
            user_reply = ET.fromstring(user_call.text)
            if len(user_reply) > 0:
                # Iterate over XML response from userid query
                for object in user_reply:
                    object_id = object.find('ObjectId').text
                    # Create REST settings to lock user pin
                    lock_url = 'https://%s/vmrest/users/%s/credential/pin' % (cuc_pub, object_id)
                    lock_data = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Credential><Locked>true</Locked></Credential>'
                    lock_header = {'Content-type':'application/xml'}
                    # Attempt to lock user pin
                    try:
                        lock_call = requests.put(lock_url, auth=HTTPBasicAuth(cuc_user, cuc_pw), verify=False, data=lock_data, headers=lock_header)
                    # If user update fails, return to main module
                    except:
                        logger.error('CUC REST access error connecting to %s' % (lock_url))
                        return
                    else:
                        # Check for valid "204" response
                        if lock_call.status_code == 204:
                            logger.info('Successfully locked voicemail PIN for user %s' % (userid_name))
                        # If pin lock fails, return to main module
                        else:
                            logger.error('Unsuccessfully locked voicemail PIN for user %s' % (userid_name))
                        # Create random pin based on desired length in JSON file
                        if pin_length < 4 or pin_length > 99:
                            pin_length = 4
                        random_pin = ''.join(['%s' % randint(0, 9) for num in range(0, pin_length)])
                        # Create REST settings to change user pin
                        pin_url = 'https://%s/vmrest/users/%s/credential/pin' % (cuc_pub, object_id)
                        pin_data = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Credential><Credentials>%s</Credentials></Credential>' % (random_pin)
                        pin_header = {'Content-type':'application/xml'}
                        # Attempt to change user pin
                        try:
                            pin_call = requests.put(pin_url, auth=HTTPBasicAuth(cuc_user, cuc_pw), verify=False, data=pin_data, headers=pin_header)
                        # If user update fails, return to main module
                        except:
                            logger.error('CUC REST access error connecting to %s' % (pin_url))
                            return
                        else:
                            # Check for valid "204" response
                            if pin_call.status_code == 204:
                                logger.info('Successfully changed voicemail PIN to random %d digit number for user %s' % (pin_length, userid_name))
                            # If pin change fails, return to main module
                            else:
                                logger.error('Unsuccessfully changed voicemail PIN to random %d digit number for user %s' % (pin_length, userid_name))
                            return
            # If CUC userid is not found, return to main module
            else:
                logger.info('No CUC user %s found' % (userid_name))
                return True
    # If no CUC servers in JSON file, return to main module
    else:
        logger.error('CUC Publisher at %s unreachable' % (cuc_pub))
        return
