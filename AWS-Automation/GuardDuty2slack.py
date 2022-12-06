import re
import boto3, os, datetime
import requests
import csv

class GuardDuty(object):
    def __init__(self):
        self.gd = gd = boto3.client(
            'guardduty',
            region_name = 'ap-south-1',#os.environ.get("GD_REGION")
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_GD"),
            aws_secret_access_key=os.environ.get("AWS_SECRET_KEY_GD")
        )
        self.DEPTH = 10
        self.FINDING_COUNT = 120
        self.TIME_DELTA_IN_MINUTES = 340 # for every 10 minutes
        self.slack_channel="XXXXXXX"
        self.slack_token=os.environ.get("SLACK_TOKEN_GD")
        self.findings={}
        self.find_detail=[]

    def get_detectorids(self):
        detectorids = []
        detector = self.gd.list_detectors()
        detectorids.extend(detector['DetectorIds'])
        next_token = detector.get("NextToken")
        
        while next_token and next_token!='':
            detector = self.gd.list_detectors()
            detectorids.extend(detector['DetectorIds'],NextToken=next_token)
            next_token = detector["NextToken"]
        return detectorids
    
    def get_findingids(self,detectorid):
        criteriaUpdatedTime = int(((datetime.datetime.now()-datetime.timedelta(minutes=self.TIME_DELTA_IN_MINUTES))-datetime.datetime(1970,1,1)).total_seconds()*1000)
        depth = self.DEPTH
        findingids = []
        FindingCriteria = {'Criterion':{'updatedAt':{'Gte':criteriaUpdatedTime}}}
        finding = self.gd.list_findings(DetectorId=detectorid,FindingCriteria=FindingCriteria)
        findingids.extend(finding.get('FindingIds',[]))
        next_token = finding.get("NextToken",None)
        count=0
        while count < depth and next_token and next_token!='':
            print("i am here")
            finding = self.gd.list_findings(DetectorId=detectorid, NextToken=next_token,FindingCriteria=FindingCriteria)
            findingids.extend(finding.get('FindingIds',[]))
            next_token = finding.get("NextToken",None)
        return findingids

    def fetch_guard_duty_findings(self):
        print("Started Fetching Guard Duty Findings")
        detector_ids = self.get_detectorids()
        for detectorid in detector_ids:
            findingids = self.get_findingids(detectorid)[0:self.FINDING_COUNT]
            for finding in findingids:
                self.find_detail.append(self.gd.get_findings(DetectorId=detectorid, FindingIds=[finding]))
        
        for ele in self.find_detail:
            id=ele["Findings"][0]["Id"]
            description=ele["Findings"][0]["Description"]
            severity=ele["Findings"][0]["Severity"]
            if float(severity)>=7.0 and float(severity)<=8.9:
                severity="High"
            elif float(severity)>=4.0 and float(severity)<=6.9:
                severity="Medium"
            else:
                severity="Low"
            title=ele["Findings"][0]["Type"]
            self.findings[id]=[title,description,severity]
        if bool(self.findings):
            self.send_slack_alert()
        else:
            print("No guarduty Findings")
    
    def send_slack_alert(self):
        self.blocks=[]
        header={"Authorization":"Bearer {}".format(self.slack_token)}
        header_block={
                    "channel":self.slack_channel,
                        
                        "blocks": [
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*Guarduty Alerts*"
                                }
                                
                            },
                            {
                                "type": "divider"
                            },
                        ]


            }
        

        for key in self.findings:
            
                block= {
                                "type": "section",
                                "fields": 
                                [
                                    {
                                        "type": "mrkdwn",
                                        "text": "*Title:*\n{}".format(self.findings[key][0])
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": ">Severity:{}".format(self.findings[key][2])
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": "*Description:*\n{}".format(self.findings[key][1])
                                    }
                                
                                ]
                        }
                self.blocks.append(block)
        header_response=requests.post("https://slack.com/api/chat.postMessage",json=header_block,headers=header)
        data={
                        "channel":self.slack_channel,
                        "attachments":[{
                             "color": "#36a64f",
                             "blocks": self.blocks
                        }]
                       
                }
        body_response=requests.post("https://slack.com/api/chat.postMessage",json=data,headers=header)
    
    

if __name__ == "__main__":
    GD = GuardDuty() 
    GD.fetch_guard_duty_findings()
    print("Finished")
