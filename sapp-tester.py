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

OTRS_URL = "http://10.20.1.9"+"/otrs/nph-genericinterface.pl/Webservice/ALERTELAST_API"
OTRS_USER_PW = os.environ['OTRS_USER_PW']

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
    config = json.load(open('config.json'))

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
                    slog("d", tID, "[Check 1/x SUCCESS] QRADAR Offense was created.")
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
                    sleep(10)

        except requests.exceptions.RequestException as e:
            print(str(e))
            dlog(str(e))

    if not reCheck:
        dlog("\tOffense not yet crated.")
        return 0, ""


def testOTRS(tID, ticketNumber):
    for i in range(1, MAX_TEST_OTRS): 
        slog("d", tID, "[Check 3/x | Attempt ", i, "/", MAX_TEST_OTRS,"] Checking if OTRS is reachable and ticket exists...")
        dlog("\tConnecting to OTRS...")
        # ...
        client = Client(OTRS_URL,"SIEMUser",OTRS_USER_PW)
        client.session_restore_or_create()
        ticket = client.ticket_get_by_number(ticketNumber,articles=True)
        ticketTitle = ticket.field_get("Title")

        if str(tID) in ticketTitle:
            dlog("\tFound ticket with correct tID: ", ticketTitle)
            slog("i", tID, "[Check 3/x SUCCESS] OTRS reachable and Ticket exists.") 

            # Checking if VT result is in ticket
            MAX_TEST_OTRS_QC = MAX_TEST_OTRS - i
            for j in range(1, MAX_TEST_OTRS_QC):
                slog("d", tID, "[Quality Check | Attempt ", j, "/", MAX_TEST_OTRS_QC,"] Checking if ticket contains ticket enrichtment (VT)...")
                ticketDict = ticket.to_dct()
                articleArray = ticketDict['Ticket']['Article']

                for i in range(len(articleArray)):
                    if "API" in articleArray[i]["From"] and ("VirusTotal Scan Result for IP" in articleArray[i]["Subject"]):
                        slog("i", tID, "[Quality Check SUCCESS] Ticket contains enrichment data from VT.") 
                        return True
                sleep(5)
            slog("i", tID, "[Quality Check FAILED] Ticket contains no enrichment data from VT (tried "+str(MAX_TEST_OTRS -  i)+" times).") 
            return True # Return true, even if Quality Check failed, as it is not critical.

        sleep(10)
    return False


def testMatrix(tID, ticketNumber):
    pass

def continuePipeline(tID, ticketNumber):
    slog("i", tID, "[Check 2/x SUCCESS] OTRS Ticket was created. OTRS Ticket#", ticketNumber)
            
    # OTRS Checks
    if(testOTRS(tID, ticketNumber)): 
        # Matrix Checks
        if(testMatrix(tID, ticketNumber)):
            slog("i", tID, "[Result: PIPELINE SUCCESS] All critical checks passed successful!")
            raise SystemExit('Exiting program (0)')
        else:
            slog("w", tID, "[Result: PIPELINE FAILED] Pipeline failed at Matrix check!")
            raise SystemExit('Exiting program (-1)')
    else:
        slog("w", tID, "[Result: PIPELINE FAILED] Pipeline failed at OTRS check!")
        raise SystemExit('Exiting program (-1)')
    sleep(10)




def testID(tID):

    if tID.startswith('Q'):
        slog("i", tID, "Starting the production test with startpoint 'QRadar' with ID ", tID, "...")
        reChek = False
        for i in range(1, MAX_TEST_QRADAR):
            slog("d", tID, "[Check 1/x | Attempt ", i, "/", MAX_TEST_OTRS,"] Checking if QRadar is reachable and if Offense was created...")

            status, ticketNumber = testQradar(tID, False)
            
            if status == 1:
                for i in range(1, MAX_TEST_OTRS):
                    slog("d", tID, "[Check 2/x | Attempt ", i, "/", MAX_TEST_OTRS,"] Checking if Alerter has seen the offense and created a ticket...")
                    status, ticketNumber = testQradar(tID, True)
                    if status == 2:
                        continuePipeline(tID, ticketNumber)

            sleep(10)
        slog("w", tID, "[Result: PIPELINE FAILED] Pipeline failed for QRadar check!")

    elif tID.startswith('Q'):
        slog("i", tID, "Starting the production test with startpoint 'Kibana' with ID ", tID, "...")


    # QRadar Checks:


# << Start >>
if args.new_test:
    newTest()
elif args.id.startswith("Q") or args.id.startswith("K"):
    testID(args.id)
else:
    slog("e", str(args.id), "Couldn't start SAPP-Tester. Invalid ID.")
