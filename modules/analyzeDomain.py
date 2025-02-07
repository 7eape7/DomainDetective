#import urllib.request
import requests
from urllib import request as urllibRequest
from time import sleep
import json

class Domain():
    def __init__(self, domainName: str, urlscanKey: str, vtKey: str, outputPath: str, inputFile = False):
        self.name = domainName
        self.urlscanKey = urlscanKey
        self.vtKey = vtKey
        self.file = inputFile
        self.url = f'https://{self.name}'
        self.outputPath = outputPath
        self.reputation: str
        self.cc: str
        self.country: str

    def get(self):
        #Get target URL
        self.url = input("URL to submit: ")

    def analyze(self):
        self.analyzeURLScan()
        #self.analyzeVirusTotal()

    def getURLScan(self):
        #Submit URL to urlscan.io API
        headers = {'API-Key':f'{self.urlscanKey}','Content-Type':'application/json'}
        data = {"url": self.url, "visibility": "unlisted"}
        post_response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
        if post_response.status_code != 200:
            print(f"Could not analyze {self.url}")
            return None
        #uuid = post_response.json()['uuid']
        #result = post_response.json()['result']
        api_result = post_response.json()['api']

        #Get API results from urlscan.io
        #Waiting for submission to process...
        sleep(10)
        get_response = requests.get(api_result)
        while get_response.status_code != 200:
            #Loop 3 second wait until the submission has processed
            sleep(3)
            get_response = requests.get(api_result)
        return get_response.json()
    
    def analyzeURLScan(self):
        print(f"Analyzing {self.name}...")
        response = self.getURLScan()
        if response == None:
            return
        
        #Parse verdicts for rating reputation
        verdicts = response['verdicts']
        malicious = verdicts['overall']['malicious']
        try:
            self.cc = response['data']['requests'][0]['response']['geoip']['country']
            self.country = response['data']['requests'][0]['response']['geoip']['country_name']
        except:
            print(f"Could not get country data for {self.url}")
        if malicious:
            print(f'{self.url} IS malicious!')
            self.reputation = "malicious"
        elif not malicious:
            print(f'{self.url} is NOT malicious')
            self.reputation = "benign"

        #Parse out the screenshot URL
        screenshotURL = response['task']['screenshotURL']

        #Download the screenshot    
        ss_path = f'{self.outputPath}/{self.name}.png'
        try:
            urllibRequest.urlretrieve(screenshotURL, ss_path)
            print(f"Downloaded screenshot of {self.name} to {ss_path}")
        except:
            print("Screenshot download failed. Trying again...")
            sleep(5)
            try:
                urllibRequest.urlretrieve(screenshotURL, ss_path)
            except:
                print(f"Failed to download screenshot of {self.name}")

    #def getVirusTotal(self):
        #Submit URL to VirusTotal

    #def analyzeVirusTotal(self):