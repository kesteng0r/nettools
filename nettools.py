#/user/bin/env python2
#   $$\   $$\ $$$$$$$$\  $$$$$$\ $$$$$$$$\ $$$$$$$$\ $$\   $$\  $$$$$$\   $$$$$$\  $$$$$$$\  
#   $$ | $$  |$$  _____|$$  __$$\\__$$  __|$$  _____|$$$\  $$ |$$  __$$\ $$$ __$$\ $$  __$$\ 
#   $$ |$$  / $$ |      $$ /  \__|  $$ |   $$ |      $$$$\ $$ |$$ /  \__|$$$$\ $$ |$$ |  $$ |
#   $$$$$  /  $$$$$\    \$$$$$$\    $$ |   $$$$$\    $$ $$\$$ |$$ |$$$$\ $$\$$\$$ |$$$$$$$  |
#   $$  $$<   $$  __|    \____$$\   $$ |   $$  __|   $$ \$$$$ |$$ |\_$$ |$$ \$$$$ |$$  __$$< 
#   $$ |\$$\  $$ |      $$\   $$ |  $$ |   $$ |      $$ |\$$$ |$$ |  $$ |$$ |\$$$ |$$ |  $$ |
#   $$ | \$$\ $$$$$$$$\ \$$$$$$  |  $$ |   $$$$$$$$\ $$ | \$$ |\$$$$$$  |\$$$$$$  /$$ |  $$ |
#   \__|  \__|\________| \______/   \__|   \________|\__|  \__| \______/  \______/ \__|  \__|
#                                                                                        
#           Nettools                                                                                                                                                   
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
    return (raw_input("Continue Y / N: ")in yes)

'''
Config
'''
installDir = os.path.dirname(os.path.abspath(__file__)) + '/'
configFile = installDir + "/nettools.cfg"
print(installDir)
config = ConfigParser.RawConfigParser()
config.read(configFile)

toolDir = installDir + config.get('nettools', 'logDir')
logDir = installDir + config.get('nettools', 'logDir')
yes = config.get('nettools', 'yes').split()
color_random=[color.HEADER,color.IMPORTANT,color.NOTICE,color.OKBLUE,color.OKGREEN,color.WARNING,color.RED,color.END,color.UNDERLINE,color.LOGGING]
random.shuffle(color_random)
nettoolsLogo = color_random[0] + '''                                                                                    
                                                                                                                                   
b.             8 8 8888888888 8888888 8888888888 8888888 8888888888 ,o888888o.         ,o888888o.     8 8888           d888888o.   
888o.          8 8 8888             8 8888             8 8888    . 8888     `88.    . 8888     `88.   8 8888         .`8888:' `88. 
Y88888o.       8 8 8888             8 8888             8 8888   ,8 8888       `8b  ,8 8888       `8b  8 8888         8.`8888.   Y8 
.`Y888888o.    8 8 8888             8 8888             8 8888   88 8888        `8b 88 8888        `8b 8 8888         `8.`8888.     
8o. `Y888888o. 8 8 888888888888     8 8888             8 8888   88 8888         88 88 8888         88 8 8888          `8.`8888.    
8`Y8o. `Y88888o8 8 8888             8 8888             8 8888   88 8888         88 88 8888         88 8 8888           `8.`8888.   
8   `Y8o. `Y8888 8 8888             8 8888             8 8888   88 8888        ,8P 88 8888        ,8P 8 8888            `8.`8888.  
8      `Y8o. `Y8 8 8888             8 8888             8 8888   `8 8888       ,8P  `8 8888       ,8P  8 8888        8b   `8.`8888. 
8         `Y8o.` 8 8888             8 8888             8 8888    ` 8888     ,88'    ` 8888     ,88'   8 8888        `8b.  ;8.`8888 
8            `Yo 8 888888888888     8 8888             8 8888       `8888888P'         `8888888P'     8 888888888888 `Y8888P ,88P'  
'''
nettoolsPrompt = "nettools ~# "
alreadyInstalled = "Already Installed"
continuePrompt = "\nClick [Return] to continue"

termsAndconditions = color.NOTICE + '''
Bonjour,
Je me dedouane et je ne suit en aucun cas reponsable de l'utilisation qui serat fait de ce script.
Merci de votre lecture
Kesteng0r

Hello ,
I dedicate myself and in no case follow responsible for the use that will have certain with this tool
Thanks for reading,
kesteng0r''' + color.END

nettools2 = color.NOTICE + '''
Ce script est encore en python2 la version arrive prochainement 

This script is stay in python2 the python3 version coming 

Thanks for reading,
Kesteng0r'''

'''
Starts Menu classes
'''
def agreement():
    while not config.getboolean("nettools", "agreement"):
        clearScr
        print('termsAndconditions')
        agree = raw_input("you must agree to our terms and conditions first (Y/n)").lower()
        if agree in yes:
            config.set('nettools', 'agreement', 'true')
class nettools:
    def __init__(self):
        clearScr()
        self.createFolders()
        print (nettoolsLogo + color.RED + '''
	   }-------------{+} Coded By Kesteng0r {+}-------------{
       }--------{+} GitHub.com/Kesteng0r/nettools {+}-------{
    ''' + color.END + '''
        {1}--Ping
        {2}--Recuperation d'informations
        {3}--Phishing
        {4}--Attaque de mots de passe 
        {5}--Scan CMS(wordpress & Joomla)
        {0}--Install & Update
        {99}-- Exit\n
    ''')
        choice = raw_input(nettoolsPrompt)
        clearScr()
        if choice == "2":
            informationsGatheringMenu()
        elif choice == "3":
            PhishingMenu()
        elif choice == "4":
            passwordMenu()
        elif choice == "5":
            CmsMenu()
        elif choice == "0":
            self.update
        elif choice == "99":
            with open(config, 'wb') as configFile:
                config.write(configFile)
            sys.exit()
        elif choice == "\r" or choice == "\n" or choice =="" or choice == " ":
            self.__init__
        else:
            try:
                print(os.system(choice))
            except:
                pass
        self.completed()

    def createFolders(self):
        if not os.path.isdir(toolDir):
            os.makedirs(toolDir)
        if not os.path.isdir(logDir):
            os.makedirs(logDir)

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()

    def update(self):
        os.system("git clone --depth=1 https://github.com/kesteng0r/nettools.git")
        os.system("cd nettools && bash ./update.sh")
        os.system("nettools")

class informationsGatheringMenu:
    menuLogo = '''
    88 88b 88 888888  dP"Yb
    88 88Yb88 88__   dP   Yb
    88 88 Y88 88""   Yb   dP
    88 88  Y8 88      YbodP
    '''
    
    def __init__(self):
        clearScr
        print(self.menuLogo)
        print("  {1}--Nmap")
        print("  {2}--Setoolkit")
        print("  {3}--Host To IP")
        print("  {4}--WPScan")
        print("  {5}--CMSmap")
        print("  {6}--XSStrike")
        print("  {7}--Doork")
        print("  {8}--Crips\n  ")
        print("  {99}-Back To Main Menu \n")
        choice2 = raw_input(nettoolsPrompt)
        clearScr()
        if choice2 == "1":
            nmap()
        elif choice2 == "2":
            setoolkit()
        elif choice2 == "3":
            host2ip()
        elif choice2 == "4":
            wpscan()
        elif choice2 == "5":
            CMSmap()
        elif choice2 == "6":
            XSStrike()
        elif choice2 == "7":
            doork()
        elif choice2 == "8":
            crips()
        elif choice2 == "99":
            nettools()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()

class PhishingMenu:
    menuLogo = '''
    88""Yb 88  88 88 .dP"Y8 88 88b 88  dP""b8 
    88__dP 88  88 88 `Ybo." 88 88Yb88 dP   `" 
    88"""  888888 88 o.`Y8b 88 88 Y88 Yb  "88 
    88     88  88 88 8bodP' 88 88  Y8  YboodP 
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)
        print("{1}--SEToolkit - Tool aimed at penetration testing around Social-Engineering")
        print("{2}--SSLtrip - MITM tool that implements SSL stripping  attacks")
        print("{3}--pyPISHER - Tool to create a mallicious website for password pishing")
        print("{4}--SMTP Mailer - Tool to send SMTP mail\n ")
        print("{99}-Back To Main Menu \n")
        choiceweb= raw_input(nettoolsPrompt)
        clearScr()
        if choiceweb == "1":
            setoolkit()
        elif choiceweb == "2":
            ssls()
        elif choiceweb == "3":
            pisher()
        elif choiceweb == "4":
            smtpsend()
        elif choiceweb == "99":
            nettools()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()

class passwordMenu:
    menuLogo= '''
    88""Yb    db    .dP"Y8 .dP"Y8 Yb        dP 8888b.
    88__dP   dPYb   `Ybo." `Ybo."  Yb  db  dP   8I  Yb
    88"""   dP__Yb  o.`Y8b o.`Y8b   YbdPYbdP    8I  dY
    88     dP""""Yb 8bodP' 8bodP'    YP  YP    8888Y"
    '''

    def __init__(self):
        clearScr()
        print(self.menuLogo)
        print("{1}--Cupp - Common User Passwords Profiler")
        print("{2}--BruteX - Automatically bruteforces all services running on a target\n")
        print("{99}-Back To Main Menu \n")
        choice = raw_input("passwd ~# ")
        clearScr()
        if choice == "1":
            cupp()
        elif choice == "2":
            brutex()
        elif choice == "99":
            nettools()
        else:
            self.__init__()
        self.completed()

    def completed(self):
        raw_input("Completed, click return to go back")
        self.__init__()
class CmsMenu:
    menuLogo = '''
        dP""b8 8b    d8 .dP"Y8  dP""b8    db    88b 88 
        dP   `" 88b  d88 `Ybo." dP   `"   dPYb   88Yb88 
        Yb      88YbdP88 o.`Y8b Yb       dP__Yb  88 Y88 
        YboodP 88 YY 88 8bodP'  YboodP dP""""Yb 88  Y8 
        '''

    def __init__(self):
            clearScr()
            print(self.menuLogo)
            print ("{1}--CMSmap")
            print ("{2}-- wpscan")
            print ("{3}-- Wordpress & joomla scanner")
            print ("{4}-- Wordpress Exploit Scanner")
            print ("{5}-- Wordpress Plugins Scanner")
            print ("{6}-- Joomla! 1.5 -3.4.5 remote code execution")
            print ("{99}-- Back to menu")
            choice3 = raw_input(nettoolsPrompt)
            clearScr()
            if choice3 == "1":
                CMSmap()
            elif choice3 == "2":
                wpscan()
            elif choice3 == "3":
                wppjmla()
            elif choice3 == "4":
                wpminiscanner()
            elif choice3 == "5":
                wppluginscanner()
            elif choice3 == "99":
                nettools()
            else:
                self.__init__()
            self.completed()

            def completed(self):
                raw_input("Completed, click return to go back")
                self.__init__()

class cupp:
    cuppLogo = '''
     dP""b8 88   88 88""Yb 88""Yb
    dP   `" 88   88 88__dP 88__dP
    Yb      Y8   8P 88"""  88"""
     YboodP `YbodP' 88     88
     '''

    def __init__(self):
        self.installDir = toolDir + "cupp"
        self.gitRepo = "https://github.com/Mebus/cupp.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.cuppLogo)
        self.run()

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))

    def run(self):
        os.system("python %s/cupp.py -i" % self.installDir)
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


class wpscan:
    wpscanLogo = '''
    Yb        dP 88""Yb .dP"Y8  dP""b8    db    88b 88
     Yb  db  dP  88__dP `Ybo." dP   `"   dPYb   88Yb88
      YbdPYbdP   88"""  o.`Y8b Yb       dP__Yb  88 Y88
       YP  YP    88     8bodP'  YboodP dP""""Yb 88  Y8
    '''

    def __init__(self):
        self.installDir = toolDir + "wpscan"
        self.gitRepo = "https://github.com/wpscanteam/wpscan.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.wpscanLogo)
        target = raw_input("   Enter a Target: ")
        self.menu(target)

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))

    def menu(self, target):
        clearScr()
        print(self.wpscanLogo)
        print("   WPScan for: %s\n" % target)
        print("   {1}--Username Enumeration [--enumerate u]")
        print("   {2}--Plugin Enumeration [--enumerate p]")
        print("   {3}--All Enumeration Tools [--enumerate]\n")
        print("   {99}-Return to information gathering menu \n")
        response = raw_input("wpscan ~# ")
        clearScr()
        logPath = "../../logs/wpscan-" + \
            strftime("%Y-%m-%d_%H:%M:%S", gmtime()) + ".txt"
        wpscanOptions = "--no-banner --random-agent --url %s" % target
        try:
            if response == "1":
                os.system(
                    "ruby tools/wpscan/wpscan.rb %s --enumerate u --log %s" % (wpscanOptions, logPath))
                response = raw_input(continuePrompt)
            elif response == "2":
                os.system(
                    "ruby tools/wpscan/wpscan.rb %s --enumerate p --log %s" % (wpscanOptions, logPath))
                response = raw_input(continuePrompt)
            elif response == "3":
                os.system(
                    "ruby tools/wpscan/wpscan.rb %s --enumerate --log %s" % (wpscanOptions, logPath))
                response = raw_input(continuePrompt)
            elif response == "99":
                pass
            else:
                self.menu(target)
        except KeyboardInterrupt:
            self.menu(target)


class CMSmap:
    CMSmapLogo = '''
     dP""b8 8b    d8 .dP"Y8 8b    d8    db    88""Yb
    dP   `" 88b  d88 `Ybo." 88b  d88   dPYb   88__dP
    Yb      88YbdP88 o.`Y8b 88YbdP88  dP__Yb  88"""
     YboodP 88 YY 88 8bodP' 88 YY 88 dP""""Yb 88
    '''

    def __init__(self):
        self.installDir = toolDir + "CMSmap"
        self.gitRepo = "https://github.com/Dionach/CMSmap.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.CMSmapLogo)
        target = raw_input("   Enter a Target: ")
        self.run(target)
        response = raw_input(continuePrompt)

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))

    def run(self, target):
        logPath = "logs/cmsmap-" + \
            strftime("%Y-%m-%d_%H:%M:%S", gmtime()) + ".txt"
        try:
            os.system("python %s/cmsmap.py -t %s -o %s" %
                      (self.installDir, target, logPath))
        except:
            pass


class XSStrike:
    XSStrikeLogo = '''
    Yb  dP .dP"Y8 .dP"Y8 888888 88""Yb 88 88  dP 888888
     YbdP  `Ybo." `Ybo."   88   88__dP 88 88odP  88__
     dPYb  o.`Y8b o.`Y8b   88   88"Yb  88 88"Yb  88""
    dP  Yb 8bodP' 8bodP'   88   88  Yb 88 88  Yb 888888
    '''

    def __init__(self):
        self.installDir = toolDir + "XSStrike"
        self.gitRepo = "https://github.com/UltimateHackers/XSStrike.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.XSStrikeLogo)
        self.run()
        response = raw_input(continuePrompt)

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("pip install -r %s/requirements.txt" % self.installDir)

    def run(self):
        os.system("python %s/xsstrike" % self.installDir)


class doork:
    doorkLogo = '''
    8888b.   dP"Yb   dP"Yb  88""Yb 88  dP
     8I  Yb dP   Yb dP   Yb 88__dP 88odP
     8I  dY Yb   dP Yb   dP 88"Yb  88"Yb
    8888Y"   YbodP   YbodP  88  Yb 88  Yb
    '''

    def __init__(self):
        self.installDir = toolDir + "doork"
        self.gitRepo = "https://github.com/AeonDave/doork.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.doorkLogo)
        target = raw_input("   Enter a Target: ")
        self.run(target)
        response = raw_input(continuePrompt)

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("pip install beautifulsoup4 requests Django==1.11")

    def run(self, target):
        if not "http://" in target:
            target = "http://" + target
        logPath = "logs/doork-" + \
            strftime("%Y-%m-%d_%H:%M:%S", gmtime()) + ".txt"
        try:
            os.system("python %s/doork.py -t %s -o %s" %
                      (self.installDir, target, logPath))
        except KeyboardInterrupt:
            pass


class crips:
    cripsLogo = '''
     dP""b8 88""Yb 88 88""Yb .dP"Y8
    dP   `" 88__dP 88 88__dP `Ybo."
    Yb      88"Yb  88 88"""  o.`Y8b
     YboodP 88  Yb 88 88     8bodP'
    '''

    def __init(self):
        self.installDir = toolDir + "Crips"
        self.gitRepo = "https://github.com/Manisso/Crips.git"

        if not self.installed():
            self.install()
        clearScr()
        print(self.cripsLogo)
        self.run()

    def installed(self):
        return (os.path.isdir(self.installDir) or os.path.isdir("/usr/share/doc/Crips"))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        os.system("bash %s/install.sh" % self.installDir)

    def run(self):
        try:
            os.system("crips")
        except:
            pass

def ssls():
    print('''sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping
    attacks.
    It requires Python 2.5 or newer, along with the 'twisted' python module.''')
    if yesOrNo():
        os.system("git clone --depth=1 https://github.com/moxie0/sslstrip.git")
        os.system("apt-get install python-twisted-web")
        os.system("python sslstrip/setup.py")
    else:
        sniffingSpoofingMenu.completed("SSlStrip")

def smtpsend():
    os.system("wget http://pastebin.com/raw/Nz1GzWDS --output-document=smtp.py")
    clearScr()
    os.system("python smtp.py")


def pisher():
    os.system("wget http://pastebin.com/raw/DDVqWp4Z --output-document=pisher.py")
    clearScr()
    os.system("python pisher.py")

class brutex:
    def __init__(self):
        self.installDir = toolDir + "brutex"
        self.gitRepo = "https://github.com/1N3/BruteX.git"

        if not self.installed():
            self.install()
        clearScr()
        self.run()

    def installed(self):
        return (os.path.isdir(self.installDir))

    def install(self):
        os.system("git clone --depth=1 %s %s" %
                  (self.gitRepo, self.installDir))
        if not os.path.isdir("/usr/share/brutex"):
            os.makedirs("/usr/share/brutex")
        os.system("cd %s && chmod +x install.sh && ./install.sh" % self.installDir)

    def run(self):
        target = raw_input("Enter Target IP: ")
        os.system("brutex %s" % target)

def wppluginscan():
    Notfound = [404, 401, 400, 403, 406, 301]
    sitesfile = raw_input("sites file: ")
    filepath = raw_input("Plugins File: ")

    def scan(site, dir):
        global resp
        try:
            conn = httplib.HTTPConnection(site)
            conn.request('HEAD', "/wp-content/plugins/" + dir)
            resp = conn.getresponse().status
        except Exception as message:
            print("Cant Connect:" + message) 
            pass

def wppjmla():

    ipp = raw_input('Enter Target IP: ')
    sites = bing_all_grabber(str(ipp))
    wordpress = check_wordpress(sites)
    joomla = check_joomla(sites)
    for ss in wordpress:
        print ss
    print '[+] Found ! ', len(wordpress), ' Wordpress Websites'
    print '-' * 30 + '\n'
    for ss in joomla:
        print ss

    print '[+] Found ! ', len(joomla), ' Joomla Websites'

    print '\n'

def wpminiscanner():
    ip = raw_input('Enter IP: ')
    sites = bing_all_grabber(str(ip))
    wordpress = check_wordpress(sites)
    wpstorethemeremotefileupload = check_wpstorethemeremotefileupload(sites)
    wpcontactcreativeform = check_wpcontactcreativeform(sites)
    wplazyseoplugin = check_wplazyseoplugin(sites)
    wpeasyupload = check_wpeasyupload(sites)
    wpsymposium = check_wpsymposium(sites)
    for ss in wordpress:
        print ss
    print '[*] Found, ', len(wordpress), ' wordpress sites.'
    print '-' * 30 + '\n'
    for ss in wpstorethemeremotefileupload:
        print ss
    print '[*] Found, ', len(
        wpstorethemeremotefileupload), ' wp_storethemeremotefileupload exploit.'
    print '-' * 30 + '\n'
    for ss in wpcontactcreativeform:
        print ss
    print '[*] Found, ', len(wpcontactcreativeform), ' wp_contactcreativeform exploit.'
    print '-' * 30 + '\n'
    for ss in wplazyseoplugin:
        print ss
    print '[*] Found, ', len(wplazyseoplugin), ' wp_lazyseoplugin exploit.'
    print '-' * 30 + '\n'
    for ss in wpeasyupload:
        print ss
    print '[*] Found, ', len(wpeasyupload), ' wp_easyupload exploit.'
    print '-' * 30 + '\n'
    for ss in wpsymposium:
        print ss

    print '[*] Found, ', len(wpsymposium), ' wp_sympsiup exploit.'

    print '\n'
############################


if __name__ == "__main__":
    try:
        agreement()
        nettools()
    except KeyboardInterrupt:
        print(" Finishing up...\n")
        time.sleep(0.25)

def bing_all_grabber(s):

    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + \
                s + "+&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib2.URLError:
            pass

    final = unique(lista)
    return final

def check_wordpress(sites):
    wp = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-login.php').getcode() == 200:
                wp.append(site)
        except:
            pass

    return wp


def check_joomla(sites):
    joomla = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'administrator').getcode() == 200:
                joomla.append(site)
        except:
            pass

    return joomla

def check_wpstorethemeremotefileupload(sites):
    wpstorethemeremotefileupload = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-content/themes/WPStore/upload/index.php').getcode() == 200:
                wpstorethemeremotefileupload.append(site)
        except:
            pass

    return wpstorethemeremotefileupload


def check_wpcontactcreativeform(sites):
    wpcontactcreativeform = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-content/plugins/sexy-contact-form/includes/fileupload/index.php').getcode() == 200:
                wpcontactcreativeform.append(site)
        except:
            pass

    return wpcontactcreativeform


def check_wplazyseoplugin(sites):
    wplazyseoplugin = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-content/plugins/lazy-seo/lazyseo.php').getcode() == 200:
                wplazyseoplugin.append(site)
        except:
            pass

    return wplazyseoplugin


def check_wpeasyupload(sites):
    wpeasyupload = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-content/plugins/easy-comment-uploads/upload-form.php').getcode() == 200:
                wpeasyupload.append(site)
        except:
            pass

    return wpeasyupload


def check_wpsymposium(sites):
    wpsymposium = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-symposium/server/file_upload_form.php').getcode() == 200:
                wpsycmium.append(site)
        except:
            pass

    return wpsymposium

def check_wpsymposium(sites):
    wpsymposium = []
    for site in sites:
        try:
            if urllib2.urlopen(site + 'wp-symposium/server/file_upload_form.php').getcode() == 200:
                wpsycmium.append(site)
        except:
            pass

    return wpsymposium
