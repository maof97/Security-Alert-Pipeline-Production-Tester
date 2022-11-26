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

from logging_helper import rlog
from logging_helper import dlog

# CONSTANTS
MAX_TEST_QRADAR = 500 # 10 second wait for every round
MAX_TEST_OTRS = 50

# Instantiate the tester...
parser = argparse.ArgumentParser(description='SAPP-Tester')
parser.add_argument('--test-id', type=int)
parser.add_argument('--new-test', action='store_true')
args = parser.parse_args()


def newTest():
    dlog("Will start a new Test...")
    id = random.randint(0,99999999)
    line="SAPP-Test Initiator is True . Keyword=QUEBEC. ID='"+str(id)+"'"
    rlog("i", id, line)
    rlog("i", id, "Startet a new test just now. Test ID=", str(id))
    testID(id)

class QRadar():

    def __init__(self, config):
        self.client = qradar_helper.TokenClient(
            config["host"],
            os.environ['QRADAR_API_TOKEN'],
        )

    def get_offenses(self, tID):
        fields = ["id", "description", "start_time", "rules", "categories", "credibility", "device_count", "log_sources", "magnitude", "offense_source", "relevance", "severity"]
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
            rlog("e", "0", str(e))
            rlog("e", "0", e.response.text)
            exit()
        return offenses

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
            rlog("e", "0", str(e))
            rlog("e", "0", e.response.text)
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
            rlog("e", "0", str(e))
            rlog("e", "0", e.response.text)

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
    dlog("\t{:d} new offenses".format(len(offenses)))
    if not offenses:
        return False

    # QRadar Rules
    rules = {}
    for offense in offenses:
        for rule in offense["rules"]:
            rules[rule["id"]] = {}
    for rule_id in rules.keys():
        rules[rule_id] = qradar.get_rule(rule_id)
    for offense in offenses:
        for i in range(len(offense["rules"])):
            offense["rules"][i] = rules[offense["rules"][i]["id"]]
        offense["start_time"] = datetime.datetime.fromtimestamp(
            offense["start_time"]/1000,
            tz=dateutil.tz.gettz("Europe/Berlin"),
        )

    # Link to offense
    for offense in offenses:
        offense["url"] = "https://{:s}/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId={:d}".format(
            config["QRadar"]["host"],
            offense["id"],
        )

    for offense in offenses:
        try:
            # QRadar Tag and Note
            qradar.create_note(offense["id"], tID)
            if offense["offense_source"] == str(tID):
                return True
        except requests.exceptions.RequestException as e:
            print(str(e))
            dlog(str(e))
            dlog(e.response.text)


def testID(tID):
    rlog("i", tID, "Starting the production test for ID ", tID, "...")

    # QRadar:
    for i in range(1, MAX_TEST_QRADAR):
        rlog("d", tID, "Checking QRadar if Offense was created (Check ", i, "/", MAX_TEST_QRADAR, ")")

        if(testQradar(tID)):
            rlog("i", tID, "QRADAR Offense was created!")
            for j in range(1, MAX_TEST_OTRS):
                rlog("d", tID, "Checking OTRS if Ticket was created (Check ", j, "/", MAX_TEST_OTRS)
                # ...
            # TODO OTRS test failed
        else:
            dlog("Offense not yet crated.")
            
        sleep(10)
    # TODO QRadar test failed.
 

# << Start >>
if args.new_test:
    newTest()
elif args.test_id > 0:
    testID(args.test_id)
