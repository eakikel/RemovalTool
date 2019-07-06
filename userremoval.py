  , KafkaException, KafkaError
from xml.etree import ElementTree as ET
import json
import threading
import logging
from logging.handlers import RotatingFileHandler
import keyring
import cucm
import cuc

# Create heartbeat message every 60 seconds
def heartbeat():
    logger.info('<<<Heartbeat>>>')
    threading.Timer(60, heartbeat).start()

if __name__ == '__main__':

    # Create logger
    log_file = 'userremoval.log'
    log_format = logging.Formatter('%(asctime)s.%(msecs)03d: %(levelname)s: %(message)s','%Y-%m-%d,%H:%M:%S')
    log_handler = RotatingFileHandler(log_file, mode='a', maxBytes=50*1024*1024, backupCount=5)
    log_handler.setFormatter(log_format)
    logger = logging.getLogger()
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)

    # Read in Kafka settings from JSON file
    settings_file = 'userremoval.json'
    with open(settings_file) as data_file:
        settings_json = json.load(data_file)
        kafka_broker = settings_json['kafka_broker']
        kafka_group = settings_json['kafka_group']
        kafka_topics = settings_json['kafka_topics']
        kafka_security = settings_json['kafka_security']
        kafka_mechanism = settings_json['kafka_mechanism']
        kafka_user = settings_json['kafka_user']
        kafka_pw = keyring.get_password("Kafka",kafka_user)

    # Set up Kafka consumer configuration
    config = {'bootstrap.servers' : kafka_broker, 'group.id' : kafka_group, 'session.timeout.ms' : 60000,
            'auto.offset.reset': 'latest', 'security.protocol' : kafka_security,
            'sasl.mechanism' : kafka_mechanism, 'sasl.username': kafka_user, 'sasl.password' : kafka_pw,
            'enable.auto.commit' : True, 'socket.keepalive.enable' : True, 'log.connection.close' : True}

    # Create Consumer instance and subscribe to topic
    c = Consumer(config)
    c.subscribe(kafka_topics)

    # Run heartbeat thread
    heartbeat()

    # Create infinate loop to constantly read messages from Kafka
    try:
        while True:
            msg = c.poll(timeout=1.0)
            # Continue if no message
            if msg is None:
                continue
            # If error message
            if msg.error():
                # If end of partition event
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    # Log end of partition event
                    logger.debug('Kafka %s [%d] reached end at offset %d' %
                        (msg.topic(), msg.partition(), msg.offset()))
                # Other error
                else:
                    raise KafkaException(msg.error())
            else:
                # Log Kafka message offset
                logger.debug('Kafka %s [%d] at offset %d with key %s:' %
                    (msg.topic(), msg.partition(), msg.offset(), str(msg.key())))
                # Check XML format of message
                try:
                    change_event = ET.fromstring(msg.value().decode())
                # Invalid XML format
                except:
                    logger.error('XML format error in Kafka message %s' % (msg.value().decode()))
            else:
                # Find message "event type"
                try:
                    event_type = change_event.find('eventType').text
                # Invalid "event type"
                except:
                    logger.error('EventType attribute not found in Kafka message %s' % (msg.value().decode()))
            else:
                # Find message "personGuid"
                try:
                    person_guid = change_event.find('personGuid').text
                # Invalid "personGuid"
                except:
                    logger.error('PersonGUID attribute Not Found in Kafka message %s' % (msg.value().decode()))
            else:
                # If "event type" is "DISABLE", call CUCM and CUC functions
                if event_type == 'DISABLE':
                    logger.info('Successfully received DISABLE message for personGUID %s' % (person_guid))
                    user_id = cucm.axl_call(person_guid)
                    if user_id:
                        cuc.rest_call(user_id)
                    else:
                        logger.info('DISABLE message for personGUID %s not processed due to user not found' % (person_guid))
except KeyboardInterrupt:
        logger.info('Aborted from keyboard')

    finally:
        # Close down consumer
        c.close()
