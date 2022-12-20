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

# CONSTANTS
MAX_TEST_QRADAR = 500 # 10 second wait for every round
MAX_TEST_OTRS = 50

OTRS_URL = "http://10.20.1.9"+"/otrs/nph-genericinterface.pl/Webservice/ALERTELAST_API"
OTRS_USER_PW = os.environ['OTRS_USER_PW']

# Instantiate the tester...
parser = argparse.ArgumentParser(description='SAPP-Tester')
parser.add_argument('--id', type=int)
parser.add_argument('--new-test', action='store_true')
args = parser.parse_args()

def newTest():
    dlog("Will start a new Test...")
    id = random.randint(0,99999999)
    slog("i", id, "Starting a new test now: SAPP-Test Initiator is True . Test-IP:'123.123.123.123' Keyword=QUEBEC. Test ID=", str(id))
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
            slog("e", "0", str(e))
            slog("e", "0", e.response.text)

    def set_closed(self, offense):
        try:
            _ = self.client.request(
                method="POST",
                path="/api/siem/offenses/" + str(offense),
                params={
                    "fields": "",
                    "status": "closed",
                    "closing_reason_id": 1
                },
            )
        except requests.exceptions.RequestException as e:
            slog("e", "0", str(e))
            slog("e", "0", e.response.text)

def default(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    raise TypeError


def testQradar(tID):
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
                slog("d", tID, "[Check 1/x SUCCESS] QRADAR Offense was created.")
                for i in range(1, MAX_TEST_OTRS):
                    slog("d", tID, "[Check 2/x | Attempt ", i, "/", MAX_TEST_OTRS,"] Checking if Alerter has seen the offense and created a ticket...")
                    
                    notes = (qradar.get_notes(offense['id']))
                    if offense["follow_up"]:
                        dlog("Notes: " , notes)

                        for note in notes:
                            if "Ticket" in note["note_text"]:
                                qradar.create_note(offense["id"], tID)
                                qradar.set_closed(offense["id"])
                                ticketID = re.findall(r'\d+', note["note_text"])[0]
                                if int(ticketID) > 0:
                                    return True, ticketID
                    else:
                        slog("d", tID, "Ticket not created in OTRS yet.")
                        dlog("Notes: " , notes)
                    sleep(10)

        except requests.exceptions.RequestException as e:
            print(str(e))
            dlog(str(e))

    dlog("\tOffense not yet crated.")        
    return False, ""


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

def testID(tID):
    slog("i", tID, "Starting the production test for ID ", tID, "...")

    # QRadar Checks:
    for i in range(1, MAX_TEST_QRADAR):
        slog("d", tID, "[Check 1/x | Attempt ", i, "/", MAX_TEST_OTRS,"] Checking if QRadar is reachable and if Offense was created...")

        done, ticketID = testQradar(tID)
        if done:
            slog("i", tID, "[Check 2/x SUCCESS] OTRS Ticket was created. OTRS Ticket#", ticketID)
            
            # OTRS Checks
            if(testOTRS(tID, ticketID)): 
                pass
        sleep(10)
    # TODO QRadar test failed.
    slog('w', tID, "Check 1/x (Check QRadar if Offense was created) - Tried " +i+ " attempts, but failed.")
 

# << Start >>
if args.new_test:
    newTest()
elif args.id > 0:
    testID(args.id)
