#!/usr/bin/python2
#Dan reference https://ipduh.com/ip/cidr/?192.0.2.0/24

import sys,re, os, socket, struct
from socket import inet_aton

USAGE = 'usage: {0} filename.txt\n'.format(sys.argv[0])


#cidr_to_netmask('10.10.1.32/27')
def cidr_to_netmask(cidr):
    network, net_bits = cidr.split('/')
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return str(network+"/"+netmask)

#netmask_to_cidr(24)
def netmask_to_cidr(netmask):
    netmask_split = netmask.split('.')
    binary_str = ''
    for octet in netmask_split:
        binary_str += bin(int(octet))[2:].zfill(8)
    return str(len(binary_str.rstrip('0')))

if len(sys.argv) != 2:
    sys.stderr.write(USAGE)
    sys.exit(1)

# validate input ip
def ip_add_validator(ipaddr_input,netmask):
    print ipaddr_input,netmask
    try:
        inet_aton(ipaddr_input)
        inet_aton(netmask)
        return "true"
        print "true dan"
    except:
        return "false"
        print "false dan"

#command sets function Dan
def object_subnet(ipaddr_input,netmask,net_name,comments_input):
    temp_line1 = "create network "+net_name+"\n"
    temp_line2 = "modify network_objects "+net_name+" ipaddr "+ipaddr_input+"\n"
    temp_line3 = "modify network_objects "+net_name+" netmask "+ netmask+"\n"
    temp_line4 = "modify network_objects "+net_name+" comments "+comments_input+"\n"  
    return temp_line1+temp_line2+temp_line3+temp_line4

def object_host(ipaddr_input,host_name,comments_input):
    temp_line1 = "create host_plain "+host_name+"\n"
    temp_line2 = "modify network_objects "+host_name+" ipaddr "+ipaddr_input+"\n"
    temp_line3 = "modify network_objects "+host_name+" comments "+comments_input+"\n"  
    return temp_line1+temp_line2+temp_line3

def object_range(ipaddr_input,range_name,comments_input):
    temp_line1 = "create address_range "+range_name+"\n"
    temp_line2 = "modify network_objects "+range_name+" ipaddr_first "+ipaddr_input+"\n"
    temp_line3 = "modify network_objects "+range_name+" ipaddr_last "+ipaddr_input+"\n"
    temp_line4 = "modify network_objects "+range_name+" comments "+comments_input+"\n"  
    return temp_line1+temp_line2+temp_line3+temp_line4

def object_Add_elements_to_group(object_input,group_name):
    temp_line1 = "create network_object_group "+group_name+"\n"
    temp_line2 = "addelement network_objects "+group_name+" '' network_objects:"+object_input+"\n"
    return temp_line1+temp_line2    


#Couting the input list
with open(str(sys.argv[1])) as f:
    total_count_address = sum(1 for _ in f)

#opening the input and output file
f_input=open(str(sys.argv[1]),'r')
f_output=open('output_list.txt', 'w')


#Command to be generated store
commands_to_object_creation = ''
commands_to_objectgrp_creation = ''

#Regular expression reference used
match_regex1 = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}$)" #format CIDR 1.1.1.1/24
match_regex2 = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}0$" #format CIDR 1.1.1.1/255.255.255.0
match_regex3 = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" #format host 1.1.1.1
match_regex4 = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$" #format range 1.1.1.1-1.1.1.255


#Loop starts 
for i in range(1, total_count_address+1):
    comments_input = "Mass_script_dan"
    read_line_ip = f_input.readline();
    read_line_ip = read_line_ip.replace("\n", '')
    read_line_ip = read_line_ip.replace("\r", '')
    read_line_ip = read_line_ip.replace(" ", '')
    read_input_address = read_line_ip.split("	")
    #read_input_address[0] - IP/Subnet, read_input_address[1] - netname ,read_input_address[3] - object group name
    
    #Step 1 IP address checker
    
    if len(read_input_address[0])!=0:
        temp_data = read_input_address[0]
        test_dan1 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}$)",read_input_address[0])
        test_dan2 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}$",read_input_address[0])
        test_dan3 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",read_input_address[0])
        test_dan4 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",read_input_address[0])
        
        #print test_dan
        if (test_dan1):
            print "format1 CIDR 1.1.1.1/24 matched", read_line_ip
            
            print "Dan"+read_input_address[0],read_input_address[1],read_input_address[2]
            #Converting to Subnet mask
            converted_ip_input = cidr_to_netmask(str(read_input_address[0]))
            ipaddr_input_split = converted_ip_input.split("/")
            ipaddr_input = str(ipaddr_input_split[0])
            netmask = str(ipaddr_input_split[1])
            
            ipaddr_calc = ipaddr_input.split('.')
            netmask_calc = netmask.split('.')
            net_name_start = [str(int(ipaddr_calc[x]) &int(netmask_calc[x]))
                              for x in range(0,4)]
            ipaddr_input = str('.'.join(net_name_start))
                
            #check if object name given
            if len(str(read_input_address[1])) >=1:
                net_name = str(read_input_address[1]) + "_" + ipaddr_input + "_" + str(netmask_to_cidr(netmask))
                
            else:
                net_name = "Net_" + "_" + ipaddr_input + "_" + str(netmask_to_cidr(netmask))
            
            #check if object group addition needed
            if len(str(read_input_address[2])) >=1:
                group_name = str(read_input_address[2])
                commands_to_objectgrp_creation = commands_to_objectgrp_creation + object_Add_elements_to_group(net_name,group_name) 

            commands_to_object_creation = commands_to_object_creation + object_subnet(ipaddr_input,netmask,net_name,comments_input)
            
        elif (test_dan2):
            print "format2 CIDR 1.1.1.1/255.255.255.0 matched", read_line_ip
            print "Dan"+read_input_address[0],read_input_address[1],read_input_address[2]
        elif (test_dan3):
            print "format3 CIDR 1.1.1.1/32 or 1.1.1.1/32 matched", read_line_ip
            print "Dan"+read_input_address[0],read_input_address[1],read_input_address[2]
        elif (test_dan4):
            print "format4 range 1.1.1.1-1.1.1.255 matched", read_line_ip
            print "Dan"+read_input_address[0],read_input_address[1],read_input_address[2]
        else:
            print "Invalid/Unidentified format: skipping: ", str(read_line_ip)
                      

f_output.write(commands_to_object_creation+commands_to_objectgrp_creation) 
f_input.close()
f_output.close()

