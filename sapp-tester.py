import os
import argparse
import random
import datetime
from time import sleep

import argparse
import datetime
from distutils.debug import DEBUG
import json

import dateutil.tz
import requests

import qradar_helper
import os
from distutils import util

from logging_helper import slog
from logging_helper import dlog

import re

from pyotrs import Client
from pyotrs.lib import Article, Ticket
from datetime import timedelta

import sys

# CONSTANTS
MAX_TEST_QRADAR = 500 # 10 second wait for every round
MAX_TEST_OTRS = 50
MAX_TEST_MATRIX = 20

CONFIG_PATH = '/root/Security-Alert-Pipeline-Production-Tester/config.json'
OTRS_URL = "http://10.20.1.9"+"/otrs/nph-genericinterface.pl/Webservice/ALERTELAST_API"
OTRS_USER_PW = os.environ['OTRS_USER_PW']
MATRIX_BOT_ACCESS_TOKEN = os.environ['MATRIX_BOT_ACCESS_TOKEN']
MATRIX_ROOM_ID = "%21qyLpnAmwoEvfFzbSgt:matrix.fulminata.eu"
MATRIX_ROOM_ID_ALERT = "%21SbWTygdrNwJUMIinGD%3Amatrix.fulminata.eu"

try:
    if os.environ['OSX_LOCAL'] == "True":
        CONFIG_PATH = 'config.json'
except:
    pass


# Instantiate the tester...
parser = argparse.ArgumentParser(description='SAPP-Tester')
parser.add_argument('--id', type=str)
parser.add_argument('--new-test', action='store_true')
parser.add_argument('--qradar-only', action='store_true')
parser.add_argument('--kibana-only', action='store_true')
args = parser.parse_args()


def newTest():
    dlog("Will start a new Test...")
    id = random.randint(0,99999999)
    if args.qradar_only or (not args.kibana_only):
        id = "Q"+str(id)
        slog("i", id, "Starting a new test with QRadar as starting point: SAPP-Test Initiator is True . Test-IP:'123.123.123.123' Keyword=QUEBEC. Test ID=", str(id))
        testID(id)
    if args.kibana_only or (not args.qradar_only):
        id = "K"+str(id)
        slog("i", id, "Starting a new test with Kibana as starting point. Test ID=", str(id))
        # ...
        testID(id)

def search(values, searchFor):
    for k in values:
        for v in values[k]:
            if searchFor in v:
                return k
    return None
class QRadar():

    def __init__(self, config):
        self.client = qradar_helper.TokenClient(
            config["host"],
            os.environ['QRADAR_API_TOKEN'],
        )

    def get_offenses(self, tID):
        fields = ["id", "description", "start_time", "rules", "categories", "credibility", "device_count", "log_sources", "magnitude", "offense_source", "relevance", "severity", "follow_up"]
        params = {
            "fields": ",".join(fields),
            "filter": "status = OPEN",
            "sort": "+id",
        }
        try:
            offenses = self.client.request(
                method="GET",
                path="/api/siem/offenses",
                params=params,
            )
        except requests.exceptions.RequestException as e:
            slog("e", "0", str(e))
            try:
                slog("e", "0", e.response.text)
            except:
                pass
            return False
        return offenses

    def get_notes(self, offense):
        try:
            x = self.client.request(
                method="GET",
                path="/api/siem/offenses/{:d}/notes".format(offense)
            )
            return x
        except requests.exceptions.RequestException as e:
            slog("e", "0", str(e))
            slog("e", "0", e.response.text)

    def get_rule(self, rule):
        fields = ["name", "type", "origin"]
        params = {
            "fields": ",".join(fields),
        }
        try:
            rule = self.client.request(
                method="GET",
                path="/api/analytics/rules/" + str(rule),
                params=params,
            )
        except requests.exceptions.RequestException as e:
            slog("e", "0", str(e))
            slog("e", "0", e.response.text)
        return rule


    def create_note(self, offense, tID):
        try:
            _ = self.client.request(
                method="POST",
                path="/api/siem/offenses/{:d}/notes".format(offense),
                params={
                    "fields": "",
                    "note_text": "Checked tID." + str(tID),
                },
            )
        except requests.exceptions.RequestException as e:
            slog("w", tID, str(e))
            slog("w", tID , e.response.text)
            return False
        return True

    def set_closed(self, offense, tID):
        try:
            _ = self.client.request(
                method="POST",
                path="/api/siem/offenses/" + str(offense),
                params={
                    "fields": "",
                    "status": 1,
                    "closing_reason_id": 1
                },
            )
        except requests.exceptions.RequestException as e:
            slog("w", tID, str(e))
            slog("w", tID , e.response.text)
            return False
        return True

def default(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    raise TypeError


def testQradar(tID, reCheck):
    requests.packages.urllib3.disable_warnings()

    # settings
    config = json.load(open(CONFIG_PATH))

    qradar = QRadar(config["QRadar"])

    # QRadar Offenses
    dlog("\tConnecting to {:s} ...".format(config["QRadar"]["host"]))
    offenses = qradar.get_offenses(tID)
    if offenses == False:
        return False, ""
    dlog("\t{:d} new offenses".format(len(offenses)))
    if not offenses:
        return False


    # Link to offense
    for offense in offenses:
        offense["url"] = "https://{:s}/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId={:d}".format(
            config["QRadar"]["host"],
            offense["id"],
        )

    for offense in offenses:
        try:
            #dlog(offense)
            #dlog(notes)

            # QRadar Tags and Note 
            if offense["offense_source"] == str(tID):
                if not reCheck:
                    slog("d", tID, "[Check 1/4 SUCCESS] QRADAR Offense was created.")
                    # Return to Re-Check if note is in offense now.        
                    return 1, ""
                else:
                    # Re-Fetch Offense for updates
                    notes = (qradar.get_notes(offense['id']))

                    if offense["follow_up"]:
                        dlog("Notes: " , notes)

                        for note in notes:
                            if "Ticket" in note["note_text"]:
                                ticketID = re.findall(r'\d+', note["note_text"])[0]
                                if int(ticketID) > 0:
                                    # Closing dummy offense
                                    if not (qradar.create_note(offense["id"], tID) and qradar.set_closed(offense["id"], tID)):
                                        slog("w", tID, "Failed to close dummy offense.")
                                    return 2, ticketID
                    else:
                        slog("d", tID, "Ticket not created in OTRS yet.")
                        dlog("Notes: " , notes)
                    

        except requests.exceptions.RequestException as e:
            print(str(e))
            dlog(str(e))

    if not reCheck:
        dlog("\tOffense not yet crated.")
        return 0, ""
    else:
        return 1, ""


def testOTRS(tID, ticketNumber):
    for i in range(1, MAX_TEST_OTRS): 
        slog("d", tID, "[Check 3/4 | Attempt ", i, "/", MAX_TEST_OTRS,"] Checking if OTRS is reachable and ticket exists...")
        dlog("\tConnecting to OTRS...")
        # ...
        client = Client(OTRS_URL,"SIEMUser",OTRS_USER_PW)
        client.session_restore_or_create()
        ticket = client.ticket_get_by_number(ticketNumber,articles=True)
        ticketTitle = ticket.field_get("Title")

        if str(tID) in ticketTitle:
            dlog("\tFound ticket with correct tID: ", ticketTitle)
            slog("i", tID, "[Check 3/4 SUCCESS] OTRS reachable and Ticket exists.") 

            # Checking if VT result is in ticket
            MAX_TEST_OTRS_QC = MAX_TEST_OTRS - i
            for j in range(1, MAX_TEST_OTRS_QC):
                slog("d", tID, "[Quality Check | Attempt ", j, "/", MAX_TEST_OTRS_QC,"] Checking if ticket contains ticket enrichtment (VT)...")
                # ticket = client.ticket_get_by_number(ticketNumber,articles=True)  TODO REANABLE 
                ticketDict = ticket.to_dct()
                articleArray = ticketDict['Ticket']['Article']

                for i in range(len(articleArray)):
                    if "API" in articleArray[i]["From"] and ("VirusTotal Scan Result for IP" in articleArray[i]["Subject"]):
                        slog("i", tID, "[Quality Check SUCCESS] Ticket contains enrichment data from VT.") 
                        return True
                #sleep(5) TODO REANABLE SLEEP
            slog("i", tID, "[Quality Check FAILED] Ticket contains no enrichment data from VT (tried "+str(MAX_TEST_OTRS -  i)+" times).") 
            sendWarning(tID, -1)
            return True # Return true, even if Quality Check failed, as it is not critical.

        sleep(10)
    return False





def sendWarning(tID, level):
    try:
        req_url = "https://matrix.fulminata.eu/_matrix/client/r0/rooms/"+MATRIX_ROOM_ID_ALERT+"/send/m.room.message?access_token="+MATRIX_BOT_ACCESS_TOKEN
        #AT_PERSON = "@martin "
        msg = ""

        if level == 4:
            msg = "ℹ️ SAPP-Tester: [Priorität "+str(level)+"] [SAPP Test failed at Check 4/4 (Check Matrix)] Please check Matrix."
        if level == 3:
            msg = "ℹ️ SAPP-Tester: [Priorität "+str(level)+"] [SAPP Test failed at Check 3/4 (Check OTRS Ticket)] Please check OTRS."
        if level == 2:
            msg = "⚠️ SAPP-Tester: [Priorität "+str(level)+"] [SAPP Test failed at Check 2/4 (Check if Offense generated OTRS Ticket)] Please check OTRS-API-ORCHESTRATOR for errors or warnings."
        if level == 1 and tID.startswith("Q"):
            msg = "❗️ SAPP-Tester: [Priorität "+str(level)+"] [SAPP Test failed at Check 1/4 (Check if QRadar generated Offense)] Please check QRadar!"
        elif level == 1 and tID.startswith("K"):
            msg = "❗️ SAPP-Tester: [Priorität "+str(level)+"] [SAPP Test failed at Check 1/4 (Check if Kibana generated alert)] Please check Kibana!"
        if level == 0:
            msg = "❗️❗️ SAPP-Tester: [Priorität "+str(level)+"] [SAPP Test failed before Check 1/4] Check if SAPP-Tester itself works correctly!"
        if level == -1:
            msg = "ℹ️ SAPP-Tester: [Priorität 4] [SAPP Quality Check failed (Check if ticket enrichtment works) Check VT API limit."

        msg=msg+" | tID: "+tID
        d = {"msgtype":"m.text", "body":msg}
        res = requests.post(req_url, json=d, verify=False)
        if(str(res.status_code) != '200'):
            print("[WARNING] Could not send Matrix Alert in Alert_Ticket() -> Reponse not OK (200)")
            print(res.json())
    except:
        try:
            slog("e", tID, "Could not send warning message.")
        except:
            slog("e", "?", "Could not send warning message. Also could not get tID.")  





def testMatrix(tID, ticketNumber): 
    # Set the access token for the user "siem_bot"
    access_token = MATRIX_BOT_ACCESS_TOKEN
    # Set the room ID for the room that you want to retrieve messages from
    room_id = MATRIX_ROOM_ID

    # Set the authorization header
    headers = {"Authorization": f"Bearer {MATRIX_BOT_ACCESS_TOKEN}"}

    # Make the request to the API
    url = "https://matrix.fulminata.eu/_matrix/client/r0/sync?filter=0&timeout=0&since=s25625_170248_3004_30386_18828_15_3972_204_0&rooms=={{{room_id}}}"

    for i in range(1, MAX_TEST_MATRIX):
        slog("d", tID, "[Check 4/4 | Attempt ", i, "/", MAX_TEST_OTRS,"] Checking if alert message was send to Matrix...")
        response = requests.get(url, headers=headers)

        # Check the status code of the response
        if response.status_code == 200:
            # Parse the response body as a JSON object
            response_data = json.loads(response.content)
            print(response_data)
            # Extract the messages from the response data
            messages = [event["content"]["body"] for event in response_data["rooms"]["join"]["!qyLpnAmwoEvfFzbSgt:matrix.fulminata.eu"]["timeline"]["events"]]
            # Print the messages
            dlog("\tLast Matrix Messages: ", messages)

            # Search the messages for the string "ABC"
            for message in messages:
                if tID in message:
                    slog("i", tID, "[Check 4/4 SUCCESS] Alert message was sent to matrix.")
                    return True
                else:
                    dlog("\tMessage not found yet.")

        else:
            # Print the error message
            slog("w", tID, "Error, got error message in reponse from Matrix:")
            slog("w", tID, f"Error {response.status_code}: {response.text}")
        sleep(10)
    return False




def continuePipeline(tID, ticketNumber):
    slog("i", tID, "[Check 2/4 SUCCESS] OTRS Ticket was created. OTRS Ticket#", ticketNumber)
            
    # OTRS Checks
    if(testOTRS(tID, ticketNumber)): 
        # Matrix Checks
        if(testMatrix(tID, ticketNumber)):
            slog("i", tID, "[Result: PIPELINE SUCCESS] All critical checks passed successful!")
            dlog('Exiting program (0)')
            sys.exit()
        else:
            slog("w", tID, "[Result: PIPELINE FAILED] Pipeline failed at Matrix check!")
            sendWarning(tID, 4)
            sys.exit()
    else:
        slog("w", tID, "[Result: PIPELINE FAILED] Pipeline failed at OTRS check!")
        sendWarning(tID, 3)
        sys.exit()
    sleep(10)




def testID(tID):

    if tID.startswith('Q'):
        slog("i", tID, "Starting the production test with startpoint 'QRadar' with ID ", tID, "...")
        reChek = False
        for i in range(1, MAX_TEST_QRADAR):
            slog("d", tID, "[Check 1/4 | Attempt ", i, "/", MAX_TEST_OTRS,"] Checking if QRadar is reachable and if Offense was created...")

            status, ticketNumber = testQradar(tID, False)
            
            if status == 1:
                for i in range(1, MAX_TEST_OTRS):
                    slog("d", tID, "[Check 2/4 | Attempt ", i, "/", MAX_TEST_OTRS,"] Checking if Alerter has seen the offense and created a ticket...")
                    status, ticketNumber = testQradar(tID, True)
                    if status == 2:
                        continuePipeline(tID, ticketNumber)
                    sleep(10)
                slog("w", tID, "[Result: PIPELINE FAILED] Pipeline failed for QRADAR <-> OTRS check!")
                sendWarning(tID, 2)
                sys.exit()
            sleep(10)

        slog("w", tID, "[Result: PIPELINE FAILED] Pipeline failed for QRadar check!")
        sendWarning(tID, 1)
        sys.exit()

    elif tID.startswith('Q'):
        slog("i", tID, "Starting the production test with startpoint 'Kibana' with ID ", tID, "...")


    # QRadar Checks:


# << Start >>
try:
    if args.new_test:
        newTest()
    elif args.id.startswith("Q") or args.id.startswith("K"):
        testID(args.id)
    else:
        slog("e", str(args.id), "Couldn't start SAPP-Tester. Invalid ID.")
        sendWarning("?", 0)
except Exception as e:
    slog("e", "0", str(e))
    sendWarning("?", 0)
    sys.exit()


# */15 * * * * bash -c "if [ $(expr $RANDOM % 8) -eq 0 ]; then /usr/bin/python3 /root/Security-Alert-Pipeline-Production-Tester/sapp-tester.py --new-test --qradar-only; fi"
# */5 * * * * bash -c "if [ $(expr $RANDOM % 1) -eq 0 ]; then /usr/bin/python3 /root/Security-Alert-Pipeline-Production-Tester/sapp-tester.py --new-test --qradar-only; fi"