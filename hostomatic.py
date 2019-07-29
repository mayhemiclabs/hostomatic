#!/usr/bin/env python3
#
# hostomatic.py - Script that takes in IP or FQDNs and and prints 
# out information regarding their location on the Internet
#
# USAGE: ./hostomatic.py [-h] [-i INPUTFILE | -a ADDRESS] [-o OUTPUTFILE]
#
# All code Copyright (c) 2012, Ben Jackson and Mayhemic Labs -
# bbj@mayhemiclabs.com. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# * Neither the name of the author nor the names of contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys, time, dns, ipaddr, socket, pygeoip, argparse, queue, threading
from dns import resolver,reversename

private_nets = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']
num_workers = 5

host_list = queue.Queue()
ip_resolved_list = queue.Queue()

def dns_query(query_type,value):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    try:
         value = resolver.query(value,query_type)

    except dns.exception.Timeout:
        value = 'TIMEOUT'
    except dns.resolver.NXDOMAIN:
        value = 'NXDOMAIN'
    except dns.resolver.NoAnswer:
        value = 'NOANSWER'
    except:
        value = 'ERROR'

    return value

def rdns_query(ip):

        try:
                ipaddr.IPAddress(ip)
        except ValueError:
                return 'INVALID'

        result = dns_query("PTR",reversename.from_address(ip))

        if(type(result) is str):
                value = result
        else:
                value = str(result[0]).rstrip('.')

        return value

def reverse_ip(ip):
        ip_array = ip.split('.')
        ip_rev = ip_array[3] + '.' + ip_array[2] + '.' + ip_array[1] + '.' + ip_array[0]
        return ip_rev

def network_lookup(ip):

        if not is_rfc1918_address(ip):
                ip_rev = reverse_ip(ip)
                result = dns_query("TXT",ip_rev + '.origin.asn.shadowserver.org')
        else:
                result = 'PRIVATE NETWORK'
        
        values = {}        

        if(type(result) is str):
                values['as_number'] = result
                values['as_name'] = result
                values['as_netblock'] = result
                values['as_country'] = result
                values['as_domain'] = result
                values['as_isp'] = result
        else:
                as_response = str(result[0]).replace('"','')
                as_values = as_response.split('|')

                values['as_number'] = as_values[0].strip()
                values['as_netblock'] = as_values[1].strip()
                values['as_name'] = as_values[2].strip()
                values['as_country'] = as_values[3].strip()
                values['as_isp'] = as_values[4].strip()
                values['as_domain'] = '' #as_values[5].strip()

        return values


def abuse_lookup(ip):

        if not is_rfc1918_address(ip):
                ip_rev = reverse_ip(ip)
                result = dns_query("TXT",ip_rev + '.abuse-contacts.abusix.org')
        else:
                result = 'PRIVATE NETWORK'

        values = {}

        if(type(result) is str):
                values['abuse_contact'] = result
        else:
                values['abuse_contact'] = str(result[0]).replace('"','')

        return values

def is_rfc1918_address(ip):

        for net in private_nets:
                if ipaddr.IPAddress(ip) in ipaddr.IPNetwork(net):
                        return 1
        return 0

def is_ip_address(argument):
        try:
               ipaddr.IPAddress(argument)
               return 1

        except ValueError:
                return 0

def is_file(argument):
        try:
                f = open(argument, 'r+')
                return 1
        except IOError:
                return 0

def resolvomatic():
    while host_list.qsize() > 0:

        host = str(host_list.get()).split('|')

        address_info = {}
        address_info['fqdn'] = host[0]
        address_info['ip'] = host[1]
        address_info['reverse_dns'] = rdns_query(address_info['ip'])

        address_info.update(network_lookup(address_info['ip']))
        address_info.update(abuse_lookup(address_info['ip']))

        if args.geocode:
            address_info.update(gi.record_by_addr(host[1]))
        else:
            address_info['latitude'] = 0
            address_info['longitude'] = 0

        ip_resolved_list.put(address_info)

        host_list.task_done()
        time.sleep(.5)

def writeomatic():
    output.write("FQDN|IP_Address|Reverse_DNS|Abuse_Contact|AS_Number|AS_Netblock|AS_Name|AS_Country|AS_Domain|AS_ISP|Lat|Long" + "\n")
    while True:
        try:
            ip_resolved_addr = ip_resolved_list.get(True,1)
            output.write(str(ip_resolved_addr['fqdn']) + "|" + str(ip_resolved_addr['ip']) + "|" + str(ip_resolved_addr['reverse_dns'])+ "|" + 
              str(ip_resolved_addr['abuse_contact']) + "|" + str(ip_resolved_addr['as_number']) + "|" + 
              str(ip_resolved_addr['as_netblock']) + "|" + str(ip_resolved_addr['as_name']) + "|" + 
              str(ip_resolved_addr['as_country']) + "|" + str(ip_resolved_addr['as_domain']) + "|" +  
              str(ip_resolved_addr['as_isp']) + "|" + str(ip_resolved_addr['latitude']) + "|" + 
              str(ip_resolved_addr['longitude']) + "\n")
            ip_resolved_list.task_done()
        except queue.Empty:
            if host_list.qsize() > 0:
                time.sleep(1)
            else:
               return



parser = argparse.ArgumentParser(description='Look up basic information about Internet hosts')
group = parser.add_mutually_exclusive_group()
group.add_argument('-i','--inputfile', action="store", help='List of IPs/FQDNs seperated by a newline')
group.add_argument('-a','--address', action="store", help='IP/FQDN')
parser.add_argument('-o','--outputfile', action="store", help='Output file for data')
parser.add_argument('-g','--geocode', action="store_true", default=False, help='Output file for data')

args = parser.parse_args()

if args.geocode:
    gi = pygeoip.GeoIP('/opt/geoip/GeoLiteCity.dat')


if(args.outputfile):
    output = open(args.outputfile, 'w+')
else:
    output = sys.stdout

if(args.inputfile):
    file = open(args.inputfile, 'r+')

    for line in file:

        line = str(line).rstrip()

        if (is_ip_address(line)):
            host_list.put("N/A" + "|" + line)
        else:
                result = dns_query("A",line)

                if(type(result) is str):
                        host_list.put(line + "|0.0.0.0")
                else:
                        for address in result:
                                host_list.put(line + "|" + str(address))
else:
    if is_ip_address(args.address):
        host_list.put("N/A" + "|" + args.address)
    else:
        result = dns_query("A",args.address)

        if(type(result) is str):
                host_list.put(args.address + "|0.0.0.0")
        else:
                for address in result:
                        host_list.put(args.address + "|" + str(address))

for workers in range(num_workers):
    thread = threading.Thread(target=resolvomatic)
    thread.daemon = True
    thread.start()

writer = threading.Thread(target=writeomatic)
writer.start()
