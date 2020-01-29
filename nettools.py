#!/usr/bin/env python 3
#   $$\   $$\ $$$$$$$$\  $$$$$$\ $$$$$$$$\ $$$$$$$$\ $$\   $$\  $$$$$$\   $$$$$$\  $$$$$$$\  
#   $$ | $$  |$$  _____|$$  __$$\\__$$  __|$$  _____|$$$\  $$ |$$  __$$\ $$$ __$$\ $$  __$$\ 
#   $$ |$$  / $$ |      $$ /  \__|  $$ |   $$ |      $$$$\ $$ |$$ /  \__|$$$$\ $$ |$$ |  $$ |
#   $$$$$  /  $$$$$\    \$$$$$$\    $$ |   $$$$$\    $$ $$\$$ |$$ |$$$$\ $$\$$\$$ |$$$$$$$  |
#   $$  $$<   $$  __|    \____$$\   $$ |   $$  __|   $$ \$$$$ |$$ |\_$$ |$$ \$$$$ |$$  __$$< 
#   $$ |\$$\  $$ |      $$\   $$ |  $$ |   $$ |      $$ |\$$$ |$$ |  $$ |$$ |\$$$ |$$ |  $$ |
#   $$ | \$$\ $$$$$$$$\ \$$$$$$  |  $$ |   $$$$$$$$\ $$ | \$$ |\$$$$$$  |\$$$$$$  /$$ |  $$ |
#   \__|  \__|\________| \______/   \__|   \________|\__|  \__| \______/  \______/ \__|  \__|
#                                                                                        
#           Tools for web                                                                                                                                                      
#           credit : Kesteng0r

'''
imports
'''
import sys
import argparse
import os
import httplib
import subprocess
import re
import urllib2
import socket
import urllib
import sys
import json
import telnetlib
import glob
import random
import Queue
import threading
import base64
import time
import ConfigParser
from sys import argv
from commands import *
from getpass import getpass
from xml.dom import minidom
from urlparse import urlparse
from optparse import OptionParser
from time import gmtime, strftime, sleep

'''
fonctions commune 
'''
class color:
    HEADER = '\033[95m'
    IMPORTANT = '\33[35m'
    NOTICE = '\033[33m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'
    LOGGING = '\33[34m'
def clearScr():
    os.system('clear')

def yesOrNo():
    return (raw_input("Continue Y / N: " ) in yes)
'''
config
'''
installDir = os.path.dirname(os.path.abspath(__file__)) + '/'
configFile = installDir + "/nettols.cfg"
print(installDir)
config = ConfigParser.RawConfigParser()
config.read(configFile)

toolDir = installDir + config.get('nettools', 'toolDir')
logDir = installDir + config.get('nettools', 'logDir')
yes = config.get('nettools', 'yes').split()
color_random=[color.HEADER,color.IMPORTANT,color.NOTICE,color.OKBLUE,color.OKGREEN,color.WARNING,color.RED,color.END,color.UNDERLINE,color.LOGGING]
random.shuffle(color_random)
webtoolLogo = color_random[0] + '''                                                                                    
                   __              __                .__          
      ____   _____/  |_          _/  |_  ____   ____ |  |   ______
     /    \_/ __ \   __\  ______ \   __\/  _ \ /  _ \|  |  /  ___/
    |   |  \  ___/|  |   /_____/  |  | (  <_> |  <_> )  |__\___ \ 
    |___|  /\___  >__|            |__|  \____/ \____/|____/____  >
         \/     \/                                             \/ 
'''
termsAndconditions = color.notice + '''
Bonjour , 
je me dedouane et ne suit en aucun cas responsable de l'usage qu'auront certain avec cet outil
Merci de votre lecture
Kesteng0r - dev 

Hello ,
I dedicate myself and in no case follow responsible for the use that will have certain with this tool
Thanks for reading,
Kesteng0r - dev'''
'''
Start menu classes
'''
def agreement():
	while not config.getboolean("nettools", "agreement"):
	agree = raw_input("You must agree the conditions first (Y/n) ").lower()
	if agree in yes:
		config.set('nettools', 'agreement', 'true')
class nettools:
	def __init__(self):
        clearScr()
        self.createFolders()
print (nettoolslogo + color.RED + '''
	---------------------------
	----create by Kesteng0r----
	---------------------------
''' + color.END + '''
Hello, 

This is my first programme 
'''

'''
Starts Menu CLasses
'''
def agreement():
	while not config.getboolean("nettools", "agreement"),
		clearScr()
		agree = raw_input("You must agree to our terms and conditions first (Y/n) ").lower()
        if agree in yes:
            config.set('fsociety', 'agreement', 'true')

class fsociety:
    def __init__(self):
        clearScr()
        self.createFolders()
        print (webtoolslogo + color.RED + '''
       }--------------{+} Coded By Kesteng0r {+}--------------{
       }--------{+}  GitHub.com/Kesteng0r/nettools{+}--------{
    ''' + color.END + '''
       {1}--Nmap
       {2}--WPScan
       {3}--Ping
       {4}--Host2IP
       {99}-EXIT\n
     ''')
        choice = raw_input(fsocietyPrompt)
        clearScr()
        if choice == "1":
            informationGatheringMenu()
        elif choice == "2":
            passwordAttacksMenu()
        elif choice == "3":
            wirelessTestingMenu()
        elif choice == "4":
            exploitationToolsMenu()
        elif choice == "5":
            sniffingSpoofingMenu()
        elif choice == "6":
            webHackingMenu()
        elif choice == "7":
            privateWebHacking()
        elif choice == "8":
            postExploitationMenu()
        elif choice == "0":
            self.update()
        elif choice == "11":
            self.githubContributors()
        elif choice == "99":
            with open(configFile, 'wb') as configfile:
                config.write(configfile)
            sys.exit()
        elif choice == "\r" or choice == "\n" or choice == "" or choice == " ":
            self.__init__()
        else:
            try:
                print(os.system(choice))
            except:
                pass
        self.completed()
class nmap:
    nmapLogo = '''
    88b 88 8b    d8    db    88""Yb
    88Yb88 88b  d88   dPYb   88__dP
    88 Y88 88YbdP88  dP__Yb  88"""
    88  Y8 88 YY 88 dP""""Yb 88
    '''

    def __init__(self):
        self.installDir = toolDir + "nmap"
        self.gitRepo = "https://github.com/nmap/nmap.git"

        self.targetPrompt = "   Enter Target IP/Subnet/Range/Host: "

        if not self.installed():
            self.install()
            self.run()
        else:
            self.run()

    def installed(self):
        return (os.path.isfile("/usr/bin/nmap") or os.path.isfile("/usr/local/bin/nmap"))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("cd %s && ./configure && make && make install" %
                  self.installDir)

    def run(self):
        clearScr()
        print(self.nmapLogo)
        target = raw_input(self.targetPrompt)
        self.menu(target)

    def menu(self, target):
        clearScr()
        print(self.nmapLogo)
        print("   Nmap scan for: %s\n" % target)
        print("   {1}--Simple Scan [-sV]")
        print("   {2}--Port Scan [-Pn]")
        print("   {3}--Operating System Detection [-A]\n")
        print("   {99}-Return to information gathering menu \n")
        response = raw_input("nmap ~# ")
        clearScr()
        logPath = "logs/nmap-" + strftime("%Y-%m-%d_%H:%M:%S", gmtime())
        try:
            if response == "1":
                os.system("nmap -sV -oN %s %s" % (logPath, target))
                response = raw_input(continuePrompt)
            elif response == "2":
                os.system("nmap -Pn -oN %s %s" % (logPath, target))
                response = raw_input(continuePrompt)
            elif response == "3":
                os.system("nmap -A -oN %s %s" % (logPath, target))
                response = raw_input(continuePrompt)
            elif response == "99":
                pass
            else:
                self.menu(target)
        except KeyboardInterrupt:
            self.menu(target)


class setoolkit:
    def __init__(self):
        self.installDir = toolDir + "setoolkit"
        self.gitRepo = "https://github.com/trustedsec/social-engineer-toolkit.git"

        if not self.installed():
            self.install()
            self.run()
        else:
            print(alreadyInstalled)
            self.run()
        response = raw_input(continuePrompt)

    def installed(self):
        return (os.path.isfile("/usr/bin/setoolkit"))

    def install(self):
        os.system("apt-get --force-yes -y install git apache2 python-requests libapache2-mod-php \
            python-pymssql build-essential python-pexpect python-pefile python-crypto python-openssl")
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("cd %s && python setup.py install" % self.installDir)

    def run(self):
        os.system("setoolkit")


class host2ip:
    host2ipLogo = '''
    88  88  dP"Yb  .dP"Y8 888888 oP"Yb. 88 88""Yb
    88  88 dP   Yb `Ybo."   88   "' dP' 88 88__dP
    888888 Yb   dP o.`Y8b   88     dP'  88 88"""
    88  88  YbodP  8bodP'   88   .d8888 88 88
    '''

    def __init__(self):
        clearScr()
        print(self.host2ipLogo)
        host = raw_input("   Enter a Host: ")
        ip = socket.gethostbyname(host)
        print("   %s has the IP of %s" % (host, ip))
        response = raw_input(continuePrompt)

