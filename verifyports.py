#/usr/bin/python
#This script will verify that all ports associated with a network uuid are legitimately linked to a cloud server

import argparse
import json
import requests
import subprocess

port_uuid_list = []
server_uuid_list = []
server_port_uuid_list = []

class Auth:

    auth_url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    auth_headers = {'Content-type': 'application/json'}

    def __init__(self, user, api_key):
        self.user = user
        self.api_key = api_key

    def auth_call(self):
        self.auth_data = json.dumps({"auth": {'RAX-KSKEY:apiKeyCredentials': {'username': self.user, 'apiKey': self.api_key}}})
        self.auth_request = requests.post(self.auth_url, data=self.auth_data, headers=self.auth_headers)
        self.token_raw = self.auth_request.json()['access']['token']['id']
        self.token = str(self.token_raw)
        return self.token

#Find all port UUIDs associated with a network        
def find_port_api(region, token):
    port_url = "https://%s.networks.api.rackspacecloud.com/v2.0/ports" % region
    port_request_headers = {'X-Auth-Token': token}
    port_get_request = requests.get(port_url, headers=port_request_headers)
    port_return = port_get_request.text
    port_parse = json.loads(port_return)['ports']
    for port_uuid in port_parse:
        if network_uuid in port_uuid['network_id']:
            port_uuid_list.append(port_uuid['id'])

#Finds all server UUIDs so that the script can run a curl against the virtual interfaces to retrieve the port UUIDs
def find_server_uuids(region, ddi, token):
    server_url = "https://%s.servers.api.rackspacecloud.com/v2/%s/servers/detail" % (region, ddi)
    server_request_headers = {'X-Auth-Token': token}
    server_get_request = requests.get(server_url, headers=server_request_headers)
    server_return = server_get_request.text
    server_parse = json.loads(server_return)["servers"]
    for server_uuid in server_parse:
        server_uuid_list.append(server_uuid["id"])

#Retrieves port UUIDs from the server UUIDS and places them in a list to compare with the neutron port list        
def find_server_ports(region, ddi, token, network_uuid):
    for server_uuid in server_uuid_list:
        server_port_url = "https://%s.servers.api.rackspacecloud.com/v2/%s/servers/%s/os-virtual-interfacesv2" % (region, ddi, server_uuid)
        server_port_request_headers = {'X-Auth-Token': token}
        server_port_get_request = requests.get(server_port_url, headers=server_port_request_headers)
        server_port_return = server_port_get_request.text
        server_port_parse = json.loads(server_port_return)["virtual_interfaces"]
        for server_port_uuid in server_port_parse:
            server_port_uuid_list.append(server_port_uuid['id'])

#Compares the list, adds UUIDs that are not associated with any server            
def compare_and_delete_ports(region, token):
    port_delete_list = [uuid for uuid in port_uuid_list if uuid not in server_port_uuid_list]
    print "LIST OF BAD PORTS:"
    print port_delete_list
    
    if delete_ports == True:
        print "Deleting ports is not supported at the customer level at this time. Please contact Rackspace support with the list that was generated to have this corrected."

    

parser = argparse.ArgumentParser()

parser.add_argument('--network',
required=True,
default=None,
help='The network UUID of the private network')

parser.add_argument('--region',
required=True,
default=None,
help='The region of the server and cloud network')

parser.add_argument('--ddi',
required=True,
default=None,
help='The account number or DDI')

parser.add_argument('--user',
required=True,
default=None,
help='The user for the account')

parser.add_argument('--apikey',
required=True,
default=None,
help='The region of the server and cloud network')

parser.add_argument('--delete',
action='store_true',
required=False,
default=None,
help='Add this flag if you want to delete the bad ports that were listed')

args = parser.parse_args()

user = args.user
api_key = args.apikey
ddi = args.ddi
region = args.region
network_uuid = args.network
delete_ports = args.delete

token_return = Auth(user,api_key)
token = token_return.auth_call()
find_port_api(region, token)
find_server_uuids(region, ddi, token)
find_server_ports(region, ddi, token, network_uuid)
compare_and_delete_ports(region, token)
