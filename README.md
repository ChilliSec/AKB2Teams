# AKB2Teams

Queries the https://attackerkb.com API and posts a daily summary of vulnerabilities to your Microsoft Teams channel.

This script is provided in good faith and I don't believe it falls foul of Rapid7/AttackerKB's T&Cs or their API... please don't abuse their service!

Feel free to modify and enhance, it's been working fine for us in it's current form but your mileage may vary 😉

![Screenshot](https://github.com/ChilliSec/AKB2Teams/blob/main/AKB2Teams.png?raw=true)

## Prerequisites
* An AttackerKB.com account and API, register on this awesome resource provided by Rapid7 and contribute if you can!
* MS Teams with sufficient rights to create a channel and connector
  * After creating a channel, click on `[...]` then `Connectors` and then follow the steps to 'Add' an 'Incoming Webhook'  
* PyMSTeams `pip3 install pymsteams`

## Usage
* Grab the Python 3 script and sort the prereqs
* Replace `<<YOUR_APIKEY>>` with your AttackerKB API key
* Replace `https://outlook.office.com/webhook/<<YOUR_WEBHOOK>>` with your MS Teams Webhook
* I'd recommend adding a cron job to run it once per day... 
  * ` 0 7 * * 0-6 /usr/bin/python3 /scripts/akb2teams.py`
 
Please don't hammer AKB, there's no need to run it every 5 mins!

## Script Overview

Using the AttackerKB API, the script queries for 'assessments' that have been `revisedAfter` today's date minus two (the reason being that if you 'minus one' to get yesterday the API won't return anything that was revised yesterday... this works for now!).
Initially the script queried the 'topics' API, that being actual vulnerabilities, but this failed to get recent updates and would include newly assigned CVEs containing no data.
Assessments are interesting comments that others have posted  on topical vulnerabilities (such as if it's currently being exploited ITW).
 
* Grab 'assessments' that were updated 'yesterday';
* For each 'assessment' grab the corresponding 'topic' so we can get the vulnerability title, dates, scores and references;
* To keeps things short, only the first sentence of the vulnerability description and the update text are posted to MS Teams (if you want to know more click on the [AttackerKB] link!
* Sometimes formatting and hyperlinks will come through from the original post, if this is a problem we could add a function to strip the Markdown (or whatever they're using);
* Aside from providing a button for AttackerKB, the CVE reference will be parsed and buttons created for 'CVE Details' and 'NVD' as they're good resources (no need for MITRE as NVD has the same/more details and links back to them).
* Any notable links from the references section are also parsed to create explicit links. Rather than having alerts with hundreds of buttons this is currently limited to:
  * Microsoft Security Response Center (MSRC):  https://portal.msrc.microsoft.com/
  * US CERT (CISA): https://us-cert.cisa.gov/
  * Metasploit Exploit Module: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/ 😈
  * Packet Storm Exploit: http://packetstormsecurity.com
* If needs be, we could easily add additional meaningful buttons (but I didn't really see the point in parsing URLs for every vendor).

## Debugging?
* I've added a watchdog that basically counts the API results and if zero will post a message anyway, just so we know it's working;
* If you're tweaking testing, it might be a good idea to:
  * Create a new MS Teams channel and temporarily replace the Webhook so the 'good' channel doesn't get spammed (and you can delete the test channel afterwards)
  * Or, comment out the `msg.send()` lines (there are two near the bottom of the script) and then un-comment the `msg.printme()` lines to have the compiled 'message cards' dumped to the console
