from zeep import Client
from zeep.cache import SqliteCache
from zeep.transports import Transport
from zeep.plugins import HistoryPlugin
from requests import Session
from requests.auth import HTTPBasicAuth
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from xml.etree import ElementTree as ET
import json
import logging
import keyring
from servercheck import server_check

# Import logging setting from main function
logger = logging.getLogger(__name__)

# FUNTION - CUCM SQL query with Zeep response formatted completely as XML
def sql_query(axl, attrib):
    xml_string = ''
    # Attempt AXL call with SQL query
    try:
        query_result = axl.executeSQLQuery(sql = attrib)
    # SQL query error
    except Exception as ex:
        print(ex)
        logger.error('SQL Query Exception for: %s' % (attrib))
    # If successful, convert full reqsonse to XML
    else:
        if query_result['return'] is None:
            xml_string += '<row></row>'
        else:
            for row in query_result['return']['row']:
                xml_string += '<row>'
                for line in row:
                    xml_string += ET.tostring(line).decode()
                xml_string += '</row>'
    xml_string = '<return>' + xml_string + '</return>'
    return ET.fromstring(xml_string)

# FUNCTION - CUCM SQL update with Zeep response formatted completely as XML
def sql_update(axl, attrib):
    # Attempt AXL call with SQL query
    try:
        update_result = axl.executeSQLUpdate(sql = attrib)
    # SQL query error
    except:
        logger.error('SQL Update Exception for: %s' % (attrib))
    # If successful, convert full reqsonse to XML
    else:
        if update_result['return']['rowsUpdated'] < 1:
            return False
        else:
            return True

# FUNCTION - Perform all CUCM changes
def axl_call(person_guid):
    disable_warnings(InsecureRequestWarning)

    # Read in CUCM settings from JSON file
    settings_file = 'userremoval.json'
    with open(settings_file) as data_file:
        settings_json = json.load(data_file)
        cucm_pub = settings_json['cucm_pub']
        cucm_user = settings_json['cucm_user']
        cucm_pw = keyring.get_password("CUCM",cucm_user)
        wsdl_file = settings_json['wsdl_file']
        personguid_index = settings_json['personguid_index']
        safe_numbers = settings_json['safe_numbers']
        active_partition = settings_json["active_partition"]
        inactive_css = settings_json["inactive_css"]
        cfa_number = settings_json["cfa_number"]
        cfa_css = settings_json["cfa_css"]

    userid_name = ''
    server_status = server_check(cucm_pub)
    # If CUCM server defined in JSON file is reachable
    if server_status:
        # Define AXL settings
        binding_name = '{http://www.cisco.com/AXLAPIService/}AXLAPIBinding'
        axl_address = 'https://%s:8443/axl/' % (cucm_pub)
        session = Session()
        session.verify = False
        session.auth = HTTPBasicAuth(cucm_user, cucm_pw)
        transport = Transport(cache=SqliteCache(), session=session, timeout=20)
        history = HistoryPlugin()
        client = Client(wsdl=wsdl_file, transport=transport, plugins=[history])
        # Attempt to reach valid CUCM server
        try:
            axl = client.create_service(binding_name, axl_address)
        # If no CUCM servers reachable, return to main module
        except:
            logger.error('CUCM AXL access error connecting to %s' % (axl_address))
            return None
        # If valid CUCM server is reachable
        else:
            # Query for enduser pkid based on custom attribute "personGuid"
            enduser_query = "select fkenduser from customuserattributedata where tkcustomuserattribute = '%d' and value = '%s'" % (personguid_index, person_guid)
            enduser_reply = sql_query(axl, enduser_query)
            # If no users found, return to main module
            if len(enduser_reply) > 1:
                logger.error('More than one user found with personGuid %s' % (person_guid))
                return None
            # Parse response to pull enduser pkid
            for enduser in enduser_reply:
                # If enduser found
                if enduser:
                    enduser_pkid = enduser.find('fkenduser').text
                    # Query for enduser userid and phone number based on pkid
                    userid_query = "select userid,telephonenumber from enduser where pkid = '%s'" % (enduser_pkid)
                    userid_reply = sql_query(axl, userid_query)
                    # Parse response to pull enduser userid and phone number
                    for userid in userid_reply:
                        # If userid found
                        if userid:
                            userid_name = userid.find('userid').text
                            userid_number = userid.find('telephonenumber').text
                        # If no userid found, return to main module
                        else:
                            logger.info('No CUCM user found for personGuid %s' % (person_guid))
                            return None
                    # Determine number of safe numbers from JSON file
                    safe_count = len(safe_numbers)
                    safe_position = 0
                    # Iterate over each safe number
                    while safe_position < safe_count:
                        # If userid phone number is in safe number list, return to main module
                        if safe_numbers[safe_position] == userid_number:
                            logger.warning('Phone number %s is in safe number list' % (userid_number))
                            return None
                        safe_position += 1
                    # Query for all endusers based on phone number
                    number_query = "select userid from enduser where telephonenumber = '%s'" % (userid_number)
                    number_reply = sql_query(axl, number_query)
                    # If more than single user with same phone number, return to main module
                    if len(number_reply) > 1:
                        logger.error('More than one user found with phone number %s' % (userid_number))
                        return None
                    # Query pkid and name for all devices with userid
                    device_query = "select pkid, name from device where fkenduser = '%s' or fkenduser_mobility = '%s'" % (enduser_pkid, enduser_pkid)
                    device_reply = sql_query(axl, device_query)
                    # Parse response to pull device pkid and name
                    for device in device_reply:
                        # If device found
                        if device:
                            device_pkid = device.find('pkid').text
                            device_name = device.find('name').text
                            # Update all devices with userid to reset to NULL user
                            device_update = "update device set fkenduser = NULL, fkenduser_mobility = NULL where pkid = '%s'" % (device_pkid)
                            # If successful update
                            if sql_update(axl, device_update):
                                logger.info('Successfully removed user %s from device %s' % (userid_name, device_name))
                            # If update failure
                            else:
                                logger.error('Unable to remove user %s from device %s' % (userid_name, device_name))
                        # If no device found
                        else:
                            logger.info('No CUCM device found for user %s' % (userid_name))
                    # Query for partition pkid from routepartition based on JSON file entry
                    partition_query = "select pkid from routepartition where name = '%s'" % (active_partition)
                    partition_reply = sql_query(axl, partition_query)
                    # Parse response to pull partition pkid
                    for partition in partition_reply:
                        # If partition found
                        if partition:
                            partition_pkid = partition.find('pkid').text
                            # Query for blocking CSS pkid from callingsearchspace based on JSON file entry
                            css_query = "select pkid from callingsearchspace where name = '%s'" % (inactive_css)
                            css_reply = sql_query(axl, css_query)
                            # Parse response to pull blocked CSS pkid
                            for css in css_reply:
                                # If CSS found
                                if css:
                                    css_pkid = css.find('pkid').text
                                    # Update numplan to change DN to blocked CSS
                                    numplan_update = "update numplan set fkcallingsearchspace_sharedlineappear = '%s' where dnorpattern = '%s' and fkroutepartition = '%s'" % (css_pkid, userid_number, partition_pkid)
                                    # If successful update
                                    if sql_update(axl, numplan_update):
                                        logger.info('Successfully updated DN %s to CSS %s for user %s' % (userid_number, inactive_css, userid_name))
                                    # If update failure
                                    else:
                                        logger.error('Unable to change DN %s to CSS %s for user %s' % (userid_number, inactive_css, userid_name))
                                # If no blocking CSS found
                                else:
                                    logger.info('No CUCM blocking CSS found named %s' % (inactive_css))
                            # Query for CFA CSS pkid from callingsearchspace based on JSON file entry
                            cfa_query = "select pkid from callingsearchspace where name = '%s'" % (cfa_css)
                            cfa_reply = sql_query(axl, cfa_query)
                            # Parse response to pull CFA CSS pkid
                            for cfa in cfa_reply:
                                # If CFA CSS found
                                if cfa:
                                    cfa_pkid = css.find('pkid').text
                                    # Attempt to set CFA for user line
                                    try:
                                        cfa_result = axl.updateLine(pattern = userid_number, routePartitionName = {"uuid" : partition_pkid}, callForwardAll = {"destination" : cfa_number, "callingSearchSpaceName" : {"uuid" : cfa_pkid}})
                                    # AXL CFA update error
                                    except:
                                        logger.error('Unable to change CFA for DN %s and CSS %s for user %s' % (cfa_number, cfa_css, userid_name))
                                    # Successful CFA update
                                    else:
                                        logger.info('Successfully updated CFA for DN %s and CSS %s for user %s' % (cfa_number, cfa_css, userid_name))
                                # If no CFA CSS found
                                else:
                                    logger.info('No CUCM CFA CSS found named %s' % (cfa_css))
                        # If no partition found
                        else:
                            logger.info('No CUCM partition found named %s' % (active_partition))
                    # Query for devices user is logged into with extension mobility
                    em_query = "select fkdevice from extensionmobilitydynamic where fkenduser = '%s'" % (enduser_pkid)
                    em_reply = sql_query(axl, em_query)
                    # Parse response to pull EM device pkid
                    for em in em_reply:
                        # If EM found
                        if em:
                            em_device = em.find('fkdevice').text
                            # Attempt to log EM user out of device
                            try:
                                em_result = axl.doDeviceLogout(deviceName = {'uuid' : em_device})
                            # AXL EM device logout error
                            except:
                                logger.error('AXL exception atempting EM logout for user %s on device %s' % (userid_name, em_device))
                            # If successful, pull phone name compare device pkid to response
                            else:
                                # Query EM phone name
                                phone_query = "select name from device where pkid = '%s'" % (em_device)
                                phone_reply = sql_query(axl, phone_query)
                                # Parse response to pull phone name
                                for phone in phone_reply:
                                    # If phone found
                                    if phone:
                                        phone_name = phone.find('name').text
                                    else:
                                        phone_name = 'Unknown'
                                # Verify AXL resonse in bracketed uppercase format
                                em_verify = '{%s}' % (em_device.upper())
                                if em_result['return'] == em_verify:
                                    logger.info('Successfully logged out EM user %s with DN %s from device %s' % (userid_name, cfa_number, phone_name))
                                else:
                                    logger.error('Unable to log out EM user %s with DN %s from device %s' % (userid_name, cfa_number, em_device))
                # If no enduser found, return to main module
                else:
                    logger.info('No CUCM user found for personGuid %s' % (person_guid))
                return userid_name
    # If no CUCM servers in JSON file, return to main module
    else:
        logger.error('CUCM Publisher at %s unreachable' % (cucm_pub))
        return None
