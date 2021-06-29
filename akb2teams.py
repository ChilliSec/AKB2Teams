##########
# AKB2Teams
#   Grab vulnerability details from api.AttackerKB.com and post a
#   summary to a Microsoft Teams Channel via a preconfigured webhook
#
# Requirements:
#   pip3 install pymsteams
#   AttackerKB API key
#   MS Teams Webhook for the required channel
# Version History:
#   v1 - 20201019 - First blood
#   v2 - 20201021 - Duh, added user assessments so we get updates!
#   v3 - 20201023 - Updated the API URL (AKB changed it!!)
#   v4 - 20210606 - urllib3+requests SSL verification is now silenced
#   v5 - 20210623 - Argparse support
#   v6 - 20210629 - Typo fix
##########
script_name = "AKB2Teams"
script_ver = "v6 - 20210629"
##########
# Imports
from datetime import date,timedelta
import json
import pymsteams
import requests
import time
import urllib3
import argparse


##########
# Setup - Add your API and Webhook here!

parser = argparse.ArgumentParser(description='Grab vulnerability details from api.AttackerKB.com and post a summary to a Microsoft Teams Channel via a preconfigured webhook')
parser.add_argument('--api', help='API Key for AKB', required=True)
parser.add_argument('--webhook', help='Full Teams webhook address', required=True)
args = vars(parser.parse_args())

apikey = args['api']
apiurl = "https://api.attackerkb.com/v1/" # Seperate to make updates easier!
yesterday = str(date.today()-timedelta(2)) # *Two days* as 'createdAfter' excludes the specified date, effectively makinthis everything from yesterday!
assessmenturl = apiurl + "assessments?size=50&revisedAfter=" + yesterday # Use 'revisedAfter' as new events will have th set to the creation date/time (Size set to prevent us getting hammered, and it defaults to 10!)
webhook = args['webhook']
urllib3.disable_warnings()

##########
# Function to grab JSON from topic
def get_topic (id):
    topicurl = apiurl + "/topics?id=" + id
    topicresp = requests.get(topicurl, verify=False, headers={'Authorization': 'basic {}'.format(apikey)})
    topicjson = json.loads(topicresp.text)
    return(topicjson["data"][0]) # As this is a single result, we'll drop the 'data' wrapper

##########
# Function to convert scores to their verbage and set the colour
def score_to_text(score):
    score = int(score + 0.5) # Round up any x.5 scores
    scoretext = {1:["Very Low","ffc600"],
                 2:["Low","ff9000"],
                 3:["Medium","ff5b00"],
                 4:["High","ff2a00"],
                 5:["Very High","ff0000"]}
    return scoretext.get(score,["Unknown","0000ff"])

##########
# Get recent 'assessments' to catch vulnerabilties that people have assessed!
# (because just grabbing 'revised' vulnerabilties misses these updates, grr!)
assessmentresp = requests.get(assessmenturl, verify=False, headers={'Authorization': 'basic {}'.format(apikey)})
assessmentjson = json.loads(assessmentresp.text)
counter = 0 # Count the results so we can send a 'nil return' if needs be
# Parse each assessment
for assessment in assessmentjson["data"]:
    counter +=1
    # Grab the full topic
    topic = get_topic(assessment["topicId"])
    print("Processing Assessment: {} from Topic: {}".format(assessment["id"],topic["id"]))
    msg = pymsteams.connectorcard(webhook, verify=False) # Create a message to send to MS Teams
    #### START OF MESSAGE ####
    msg.title(topic["name"]) # Title taken from the vulnerability topic
    msg.color(score_to_text(max(topic["score"]["attackerValue"],topic["score"]["exploitability"]))[1]) # Highest score dines the message colour
    msg.text(str(topic["document"]).split(". ")[0]) # First sentence of the vulnerability description
    details = pymsteams.cardsection() # Create a  section for key details
    details.activityText(str(assessment["document"]).split(". ")[0]) # First sentence of the assessment
    details.addFact("Created",topic["created"]) # Date of creation
    details.addFact("Updated",assessment["revisionDate"]) # Date of the update/revision
    msg.addSection(details) # Add the section to the message
    scores = pymsteams.cardsection() # Create a section for the scores
    scores.addFact("Attacker Value",score_to_text(topic["score"]["attackerValue"])[0])
    scores.addFact("Exploitability",score_to_text(topic["score"]["exploitability"])[0])
    msg.addSection(scores) # Add the section to the message
    # Add link buttons for more information, all will have AttackerKB and others only if they're referenced
    msg.addLinkButton("AttackerKB","https://attackerkb.com/topics/{}".format(topic["id"]))
    try:
        for reference in topic["metadata"]["references"]:
            if reference.startswith("CVE-"):
                # Add links to 3rd-party sites
                msg.addLinkButton("CVE Details","https://www.cvedetails.com/cve/{}".format(reference))
                msg.addLinkButton("National Vulnerability Database","https://nvd.nist.gov/vuln/detail/{}".format(reference))
            elif reference.startswith("https://portal.msrc.microsoft.com/"):
                # Add link to Microsoft Security Response Center
                msg.addLinkButton("MSRC Advisory",reference)
            elif reference.startswith("https://us-cert.cisa.gov/"):
                # Add link to the US CERT (CISA)
                msg.addLinkButton("US-CERT Alert",reference)
            elif reference.startswith("https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/"):
                # Add link to potential Metasploit Exploit Module
                msg.addLinkButton("Metasploit Exploit",reference)
            elif reference.startswith("http://packetstormsecurity.com"):
                # Add link to Packet Storm Exploit/PoC
                msg.addLinkButton("Packet Storm Exploit",reference)
            # Could easily add more links if they're popular
    except KeyError:
        # No references to reference so carry on without them
        pass
### MAGIC HAPPENS HERE ###
    msg.send() # Post details of the vulnerability to the MS Teams Channel
    #msg.printme() # DEBUG
    time.sleep(5) # Sleep to avoid any rate limitation

# So we know the script is working, post a message when nothings found!
if counter == 0:
    msg = pymsteams.connectorcard(webhook, verify=False)
    msg.title("No updates found!")
    msg.text("&#x1F612;")
    msg.color("00ff00")
### MAGIC HAPPENS HERE ###
    msg.send()
    #msg.printme() # DEBUG

