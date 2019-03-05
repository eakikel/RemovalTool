import requests
import logging

# Import logging setting from main function
logger = logging.getLogger(__name__)

# FUNTION - Validate Cisco server application access; Receive server IP from calling module
def server_check(server):
    try:
        test_req = requests.get('https://%s:8443/' % (server), verify=False, timeout=2)
    # If server application not accessable within 2 seconds, skip server
    except:
        logger.error('Server %s is unreachable' % (server))
        return False
    # If server check receives valid "200" response, break out of iteration
    else:
        if test_req.status_code == 200:
            return True
        else:
            return False
