#!/usr/bin/python

import logging
import requests
import os, json, pickle
import mycreds
from collections import OrderedDict
requests.packages.urllib3.disable_warnings()
logger = logging.getLogger("")
#logger.setLevel(logging.DEBUG)
from string import Template
#overwrite requests logger to warning only
#logging.getLogger("requests").setLevel(logging.WARNING)


class NXAPIClient(object):

    def __init__(self, **kwargs):

        self.headers = {'content-type': 'application/json-rpc'}
        self.hostname = kwargs.get("hostname", None)
        self.username = kwargs.get("username", "username")
        self.password = kwargs.get("password", "password")
        self.port = kwargs.get("port", "8181")
        self.verify = kwargs.get("verify", False)
        self._http = "https://"
        self._session = None    # current session
        self._cookie = None     # active cookiejar
        self.cookie = kwargs.get("cookie", "cookie/%s_nxapi.cookie" % self.hostname)
        self.url = "%s%s:%s%s" % (self._http, self.hostname, self.port, '/ins')
        self.headers = {'content-type': 'application/json-rpc'}
        
        if self.hostname is None or len(self.hostname)<=0:
            raise Exception("missing or invalid argument 'hostname'")
        if self.username is None or len(self.username)<=0:
            raise Exception("missing or invalid argument 'username'")
        if self.password is None or len(self.password)<=0:
            raise Exception("missing or invalid argument 'password'")

        if os.path.isfile(self.cookie):
            try:
                with open(self.cookie) as f:
                    self._cookie = requests.utils.cookiejar_from_dict(pickle.load(f))
                    self._session = requests.Session()
                    
                    if self.is_authenticated():
                        logging.debug("successfully restored session")
                        return
                    else:
                        logging.debug("failed to restore previous session (unauthenticated)")
            except:
                logging.warn("failed to restore session from %s" % self.cookie)
        
        self.authenticate()

    def authenticate(self):
        logging.debug("creating new session for user %s to %s" % (self.username, self.url))
        self._session = requests.Session()
        
        try:
            payload = self.nxapi_payload()
            response = self._session.post(self.url, data=json.dumps(payload), auth=(self.username,self.password), headers=self.headers, verify=self.verify)
        except:
            logging.error("connection error occurred")
            return False
       
        logging.debug("session successfully created")
        self._cookie = requests.utils.dict_from_cookiejar(response.cookies)
        
        try:
            with open(self.cookie, 'w') as f:
                pickle.dump(self._cookie, f)
        
        except: logging.warn("failed to save cookie to file: %s" % self.cookie)
        
        self._session = requests.Session()
        return True

    def is_authenticated(self):
        """
        dummy request to check if the current session is valid. If 200 code is
        received then returns True else return False
        """

        if self._session is None or self._cookie is None:
            return False
        logging.debug("checking for valid authentication with request to %s" % self.url)
        try:
            payload = self.nxapi_payload()
            response = self._session.post(self.url, data=json.dumps(payload), headers=self.headers, cookies=self._cookie, verify=self.verify)
        except:
            logging.error("connection error occurred")
            return False
        
        return (response.status_code == 200)
    
    def payload_template(self,cmd,id):
        template = {"jsonrpc": "2.0",
                    "method": "cli",
                    "params": {"cmd": cmd, 
                    "version": 1}, "id": id}

        return template

    def nxapi_payload(self,cmd=["show ver"]):
        """
        prepare payload message with specific command for nxapi_call 
        """
        payload = []
        
        for i in range(len(cmd)):
            payload.append(self.payload_template(cmd[i],i+1))

        return payload

    def nxapi_call(self, cmd=["show hostname"]):
        """
        common NX-API call
        """
        print cmd
        payload = self.nxapi_payload(cmd)
        response = self._session.post(self.url, data=json.dumps(payload), headers=self.headers, cookies=self._cookie, verify=self.verify)

        if response.status_code != 200:
            logging.error("failed to create session")
        print response.json()

        return response.json()

    def get_iface_status(self, response):

        output = response['result']['body']['TABLE_interface']['ROW_interface']
        print output
        return output

    def get_iface_description(self, response):

        output = response['result']['body']['TABLE_interface']['ROW_interface']
        
        return output

    def get_iface_switchport(self, response):

        output = response['result']['body']['TABLE_interface']['ROW_interface']
        
        return output

    def get_module_errors(self, response):

        output = response['result']['body']['TABLE_interface']['ROW_interface']
        
        return output

    def get_iface_errors(self, response):

        output = response['result']['body']['TABLE_interface']['ROW_interface'][0]
        
        return output

    def get_transceiver_details(self, response):

        output = response['result']['body']['TABLE_interface']['ROW_interface'][0]
        
        return output

    def get_all_transceiver_details(self, response):

        output = response['result']['body']['TABLE_interface']['ROW_interface']
        
        return output

    def get_arp_list(self, response):

        output = response['result']['body']['TABLE_vrf']['ROW_vrf']['TABLE_adj']['ROW_adj']
        
        return output

    def get_mac_list(self, response):
        
        if 'TABLE_mac_address' in response['result']['body']:

            output = response['result']['body']['TABLE_mac_address']['ROW_mac_address']
        
            return output
        else:

            output = {}
            return output

    def get_ip_route(self, response):

        output = response['result']['body']['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']

        return output

    def get_vlan_id(self, response):

        if response['result']:

            output = response['result']['body']

            return output
        else:

            output = {}
            return output

    def get_po_list(self, response):
        
        po_list = []

        output = response['result']['body']['TABLE_channel']['ROW_channel']
        for item in output:
            po_list.append(item['group'])
        
        po_list.sort()
    
        return po_list

    def get_po_summary(self, response):

        output = response['result']['body']['TABLE_channel']['ROW_channel']

        return output

    def set_cmd(self, response):
        
        output = response
        for item in response:
            if 'error' in item:
                return False
                break
        return output

if __name__ == "__main__":
    # SETUP logging at debug level to stdout (default)
    logger = logging.getLogger("")
    logger.setLevel(logging.DEBUG)
    # overwrite requests logger to warning only
    logging.getLogger("requests").setLevel(logging.WARNING)

#Testing
    nxapi = NXAPIClient(hostname="192.168.35.40", username=mycreds.USERNAME, password=mycreds.PASSWORD)
    #dummy_conf = ["interface Eth131/1/1", "non shutdown", "interface Eth131/1/2", "shutdown"]
    #test = nxapi.get_all_transceiver_details(nxapi.nxapi_call(["show interface transceiver details"]))
    #test = nxapi.get_ip_route(nxapi.nxapi_call(["show ip route 192.168.8.120"]))
    test = nxapi.get_po_summary(nxapi.nxapi_call(["show port-channel summary"]))
    print test
