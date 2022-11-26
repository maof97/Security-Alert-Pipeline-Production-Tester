import logging, sys
from logging import config
import datetime
import os

# CONSTANTS
OSX_LOCAL_S = os.environ['OSX_LOCAL']
if OSX_LOCAL_S == "True":
    OSX_LOCAL = True
else:
    OSX_LOCAL = False

DEBUG_TO_SYSLOG = False

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s SAPP-Test %(module)s P%(process)d  %(message)s'
            },
        },
    'handlers': {
        'stdout': {
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
            'formatter': 'verbose',
            },
        'sys-logger6': {
            'class': 'logging.handlers.SysLogHandler',
            'address': '/dev/log',
            'facility': "local6",
            'formatter': 'verbose',
            },
        },
    'loggers': {
        'my-logger': {
            'handlers': ['sys-logger6','stdout'],
            'level': logging.DEBUG,
            'propagate': True,
            },
        }
    }

config.dictConfig(LOGGING)
logger = logging.getLogger("my-logger")
if OSX_LOCAL:
    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " | OSX Run: Skipping Syslog logging.")

def dlog(*msg): # Debug logging
    if not OSX_LOCAL and DEBUG_TO_SYSLOG:
        sl = ""
        for s in msg:
            sl += str(s)
        logger.debug("[D] " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ' +  str(sl))
    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ', end='')
    for m in msg:
        print(m, end='')
    print()

def rlog(type, tID, *msg):
    tID = str(tID)
    sl = ""
    for s in msg:
        sl += str(s) 
 
    if not OSX_LOCAL:  
        if type == 'i':
            logger.info("[I] [tID:" + tID + "] " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ' +  str(sl))
        if type == 'w':
            logger.warning("[W] [tID:" + tID + "] " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ' +  str(sl))
        if type == 'e':
            logger.error("[E] [tID:" + tID + "] " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ' +  str(sl))
        if type == 'd':
            logger.debug("[D] [tID:" + tID + "] " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ' +  str(sl))
    else:
        dlog(*msg)
