#!/usr/bin/env python
#_*_ coding: utf8 _*_

#This script is an interesting idea for automate things, with this script we
#can scan the net and see who is connected, if i already know which is the mac of 
#owner devices connected we can see exactly who is connected on the net, with that
#info we can automate lights, or any tasks in our computer or other things to automate

#Instructions:
#See help: python3 arpSpoofing.py --help , and you can see the info that the script need to execute
#Range: ifconfig and the range is ej: 192.162.1.1/24 and the gateway: 192.168.1.254
#set: python3 arpSpoofing.py -r 192.162.1.1/24 -g 192.168.1.254

from scapy.all import *
from colorama import Fore, init
import argparse
import sys
import os
import time

init()

chars = "\n"
macList = dict()
now = time.time() #get actual time

parse = argparse.ArgumentParser()#receive arguments through the command line
parse.add_argument("-r", "--range",help="Rango a escanear o spoofear")
parse.add_argument("-g", "--gateway",help="Gateway/puerta de enlace/router")
parse=parse.parse_args()#established arguments

def scanNet(gateway, range):
    hostsList = dict() #create a dictionary with the hosts scanned
    arpLayer = ARP(pdst=range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")#mac standar
    finalPacket = broadcast/arpLayer
    answers = srp(finalPacket, timeout=2, verbose=False)[0] #send packages again with the range and save the answers for the net    
    for a in answers:
        if a[1].psrc != gateway: #print only the hosts and their mac address with a smart design
            #print("[{}+{}] HOST: {} MAC: {}".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, a[1].psrc, a[1].hwsrc))
            hostsList.update({a[1].psrc: a[1].hwsrc}) #update the dictionary with the info collected
    
    return hostsList

def getMac(): #get mac with oowners names from txtfile
    macFile = open('macAddress.txt', 'r')
    macFile = macFile.readlines()

    for line in macFile:
        for char in chars:
            line = line.replace(char, "")#replace char innecesary
            line = line.split(',')            
            macList.update({line[0]: line[1]})#insert into a dictionary the info and the key is owner name    

def main():
    usersOnline = list()
    getMac() #update dictionary with txtfile info
    if parse.range and parse.gateway: #if the user insert correctly the options (range and gateway)
        try: 
            future = now + 10 # increment 10 seconds to actual time         
            while True: #infinite loop                
                while time.time() == future:# for each 10 seconds scan the net and get users connected to net
                    hosts = scanNet(parse.gateway,parse.range) #scan net                
                    for user in macList: #get keys from dictionary, in this case user is the key in macList
                        for ip in hosts: #ip is key form hosts dictionary and mac is the value
                            if macList[user] in hosts[ip]: #get value from key
                                if user not in usersOnline:
                                    usersOnline.append(user) 
                    for user in usersOnline:
                        print(f'{Fore.LIGHTWHITE_EX}[{Fore.LIGHTGREEN_EX}+{Fore.LIGHTWHITE_EX}] El usuario {Fore.LIGHTGREEN_EX}{user}{Fore.LIGHTWHITE_EX} actualmente esta conectado a la red')
                    usersOnline.clear()  
                    print('\n')
                    future = future + 10 #increment 10 seconds               
                    break                            
                
        except KeyboardInterrupt: #stop and exit with ctrl + c
            os.system('clear')
            exit(0)
    else: #if the user not insert correctly arguments show him the help
        os.system('python3 netHosts.py --help')

if __name__ == "__main__":
    main()