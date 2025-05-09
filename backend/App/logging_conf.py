import logging
import logstash
import logging.handlers

def setup_logging():
    logger = logging.getLogger('python-logstash-logger')
    logger.setLevel(logging.INFO)

    # Log vào file
    file_handler = logging.FileHandler('logs/app.log')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

    # Log vào Logstash
    logstash_handler = logstash.TCPLogstashHandler('logstash-host', 5959, message_type='logstash')
    logger.addHandler(logstash_handler)

    return logger
