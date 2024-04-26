import json
import logging
import os

from urllib.parse import urlencode
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import boto3
import ast




#http = urllib3.PoolManager()
session = boto3.session.Session()
SESSION_KEY={
    "aws_access_key_id":"",
        "aws_secret_access_key":"",
        "aws_session_token":""
    
}

class CloudWatchAlarmParser:
    def __init__(self, msg):
        self.msg = msg
        self.timestamp_format = "%Y-%m-%dT%H:%M:%S.%f%z"
        self.trigger = msg["Trigger"]

        if self.msg['NewStateValue'] == "ALARM":
            self.color = "danger"
        elif self.msg['NewStateValue'] == "OK":
            self.color = "good"

    def slack_data(self):
        _message = {
            'text': '<!here|here>',  # add @here to message
            'attachments': [
                {
                    'title': ": CloudWatch Alarm | Account :  "+ get_ssm_parameters_svc(self.msg['AWSAccountId']),
                    'color': self.color,
                    'fields': [
                        {
                            "title": "Alarm Name",
                            "value": self.msg["AlarmName"],
                            "short": True
                        },
                        {
                            "title": "Alarm Description",
                            "value": self.msg["AlarmDescription"],
                            "short": False
                        },
                        {
                            "title": "Trigger",
                            "value": " ".join([
                                self.trigger["Statistic"],
                                self.trigger["MetricName"],
                                self.trigger["ComparisonOperator"],
                                str(self.trigger["Threshold"]),
                                "for",
                                str(self.trigger["EvaluationPeriods"]),
                                "period(s) of",
                                str(self.trigger["Period"]),
                                "seconds."
                            ]),
                            "short": False
                        },
                        {
                            'title': 'State Reason',
                            'value': self.msg["NewStateReason"],
                            'short': False
                        },
                        {
                            'title': 'Old State',
                            'value': self.msg["OldStateValue"],
                            "short": True
                        },
                        {
                            'title': 'Current State',
                            'value': self.msg["NewStateValue"],
                            'short': True
                        }
                    ]
                }
            ]
        }
        return _message

def get_ssm_parameters_svc(accountId):
    ssm_client = boto3.client('ssm');
    svc_name=ssm_client.get_parameters(Names=['SERVICE_NAME'])['Parameters'];
    value=svc_name[0]['Value']
    # using json.loads()
    # convert dictionary string to dictionary
    res = json.loads(value)
    
    print("SERVICE_NAME : "+res[accountId])

    return res[accountId]
def get_ssm_parameters_url(channel):
    ssm_client = boto3.client('ssm');
    chnl_name=ssm_client.get_parameters(Names=['CHANNEL_NAME'])['Parameters'];
    value=chnl_name[0]['Value']
    
    
    # using json.loads()
    # convert dictionary string to dictionary
    res = json.loads(value)
    
    print("{0} WEBHOOK_URL : {1}".format(channel,res[channel]))
    return res[channel]
def get_ssm_parameters_role(accountId):
    ssm_client = boto3.client('ssm');
    chnl_name=ssm_client.get_parameters(Names=['CW_IAM_ROLE_ARN'])['Parameters'];
    value=chnl_name[0]['Value']
    # using json.loads()
    # convert dictionary string to dictionary
    res = json.loads(value)
    print("IAM_ROLE_ARN : "+res[accountId])
    return res[accountId]


class GetResourceHookURL:
    def __init__(self,accountId):
        self.sts_client=boto3.client('sts');

        #get session to target aws account.
        response = self.sts_client.assume_role(
            RoleArn=get_ssm_parameters_role(accountId),
            RoleSessionName="temp-session"
            )
        #set aws access config
        SESSION_KEY["aws_access_key_id"]=response['Credentials']['AccessKeyId']
        SESSION_KEY["aws_secret_access_key"]=response['Credentials']['SecretAccessKey']
        SESSION_KEY["aws_session_token"]=response['Credentials']['SessionToken']
        
    def get_hook_url_by_ec2_tags(self,instanceId):
        #get target instance tags (Alarm tags)
        
        ec2_client=boto3.client('ec2',  aws_access_key_id=SESSION_KEY["aws_access_key_id"],
        aws_secret_access_key=SESSION_KEY["aws_secret_access_key"],
        aws_session_token=SESSION_KEY["aws_session_token"]
        )

        #ec2_client=boto3.client('ec2');
        ec2_info=ec2_client.describe_instances(InstanceIds=[instanceId])
        for tags in ec2_info['Reservations'][0]['Instances'][0]['Tags']:
            if tags['Key'] == 'ALARM':
                hook_url=get_ssm_parameters_url(tags['Value'])

                return hook_url

    def get_hook_url_by_rds_tags(self,rdsIdentifier):
        #get target instance tags (Alarm tags)
        
        rds_client=boto3.client('rds',  aws_access_key_id=SESSION_KEY["aws_access_key_id"],
        aws_secret_access_key=SESSION_KEY["aws_secret_access_key"],
        aws_session_token=SESSION_KEY["aws_session_token"]
        )


        #ec2_client=boto3.client('ec2');
        rds_info=rds_client.describe_db_instances(DBInstanceIdentifier=rdsIdentifier)
        for tags in rds_info['DBInstances'][0]['TagList']:
            if tags['Key'] == 'ALARM':
                hook_url=get_ssm_parameters_url(tags['Value'])
                return hook_url
    def get_hook_url_by_elb_tags(self,targetGroup):
        #get target instance tags (Alarm tags)
        elb_client=boto3.client('elbv2',  aws_access_key_id=SESSION_KEY["aws_access_key_id"],
        aws_secret_access_key=SESSION_KEY["aws_secret_access_key"],
        aws_session_token=SESSION_KEY["aws_session_token"]
        )

        tg_info=elb_client.describe_tags(ResourceArns=[targetGroup])
        for tags in tg_info['TagDescriptions'][0]['Tags']:
            if tags['Key'] == 'ALARM':
                hook_url=get_ssm_parameters_url("#"+tags['Value'])
                return hook_url




def lambda_handler(event, context):
  print(json.dumps(event));
  
  ### Check Service Account and Service Channel
  
  hook_url=""
  msg=json.loads(event['Records'][0]['Sns']['Message'])
  slack_data = CloudWatchAlarmParser(msg).slack_data()
  #client=CheckService(msg['AWSAccountId'])

  if (msg['Trigger']['Namespace'] == "AWS/EC2" or msg['Trigger']['Namespace'] == "CWAgent"):
      #EC2
      for i in msg['Trigger']['Dimensions']:
          if i['name'] == "InstanceId":
              ec2_client=GetResourceHookURL(msg['AWSAccountId']);
              hook_url=ec2_client.get_hook_url_by_ec2_tags(i['value'])
  
  elif (msg['Trigger']['Namespace'] == "AWS/VPN"):
      #VPN
      hook_url=get_ssm_parameters_url("#aws-vpn-alert")
  elif msg['Trigger']['Namespace'] == "AWS/RDS":
      #RDS
      for i in msg['Trigger']['Dimensions']:
          if i['name'] == "DBInstanceIdentifier":
              rds_client=GetResourceHookURL(msg['AWSAccountId']);
              hook_url=rds_client.get_hook_url_by_rds_tags(i['value'])
  elif msg['Trigger']['Namespace'] == "AWS/ApplicationELB" or msg['Trigger']['Namespace'] == "AWS/NetworkELB":
      #ELBv2
      for i in msg['Trigger']['Dimensions']:
          if i['name'] == "TargetGroup":
              elb_client=GetResourceHookURL(msg['AWSAccountId']);
              tg_arn = "arn:aws:elasticloadbalancing:ap-northeast-2:"+msg["AWSAccountId"]+":"+i['value']
              hook_url=elb_client.get_hook_url_by_elb_tags(tg_arn)
  elif msg['Trigger']['Namespace'] == "AWS/DX":
      #DX
      hook_url=get_ssm_parameters_url("#dx_alert")


  request = Request(
        hook_url, 
        data=json.dumps(slack_data).encode(),
        headers={'Content-Type': 'application/json'}
        )
  response = urlopen(request)
  return {
        'statusCode': response.getcode(),
        'body': response.read().decode()
    }
