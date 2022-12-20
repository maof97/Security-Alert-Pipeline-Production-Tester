# Logging helper for Python with Syslog
# 
# dlog(*msg): Local (printf) Debug logging
# slog(type, id, *msg): Remote (syslog) Logging with type 'd' = debug, 'i' = informational, 'w' = warning, 'e' = error and 'id' as identifier. Implies dlog(*msg).
# rlog(id, *msg): Report Logging (one line to a seperate file with each 'id'). Implies slog('i', id, *msg).
#

import logging, sys
from logging import config
import datetime
import os

# CONSTANTS
OSX_LOCAL_S = os.environ['OSX_LOCAL']
DEBUG_TO_SYSLOG = False
PROTOCOL_PATH = "SAPP_Reports/"

if OSX_LOCAL_S == "True":
    OSX_LOCAL = True
    PROTOCOL_PATH = "SAPP_Reports/"
else:
    OSX_LOCAL = False

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
            'facility': "local6", # Change localX here
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
    sl = ""
    for s in msg:
        sl += str(s)
    rlog('d2', 0, str(sl))
    
    if not OSX_LOCAL and DEBUG_TO_SYSLOG:
        logger.debug("[D] " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ' +  str(sl))
    
    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ', end='')
    for m in msg:
        print(m, end='')
    print()

def slog(type, id, *msg):
    id = str(id)
    sl = ""
    for s in msg:
        sl += str(s) 
 
    if not OSX_LOCAL:  
        if type == 'i':
            logger.info("[I] [id:" + id + "] " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ' +  str(sl))
        if type == 'w':
            logger.warning("[W] [id:" + id + "] " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ' +  str(sl))
        if type == 'e':
            logger.error("[E] [id:" + id + "] " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ' +  str(sl))
        if type == 'd':
            logger.debug("[D] [id:" + id + "] " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | ' +  str(sl))
    else:
        dlog(*msg)
    rlog(type, id, str(sl))

def rlog(type, id, *msg):

    for file in os.listdir(PROTOCOL_PATH):
        if file.startswith("Report_" + str(id)):
            protName = file
            break
    else:
        protName = "Report_" + str(id) + "_" + datetime.datetime.now().strftime("%Y-%m-%dT%H_%M") + ".log"

    if type == "DELETE":
        os.remove(PROTOCOL_PATH + protName)

    sl = ""
    for s in msg:
        sl += str(s) 
    
    with open(PROTOCOL_PATH + protName, "a") as pf:
        pf.write(datetime.datetime.now().strftime("%H:%M:%S") + ' ['+str(type)+'] >> ' +  str(sl) + "\n")
        #pf.write("")

# Testing
#dlog("Logging local debug test.")
#slog(0, "Logging syslog test.")
#rlog(0, "Logging report test.")