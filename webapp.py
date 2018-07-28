#!/usr/bin/env python
# -*- coding: utf-8 -*-
import web
import commands
from urlgrabber.grabber import URLGrabber, URLGrabError
import string
import re
import tempfile
from time import sleep
import traceback
import os
import os.path
import tarfile
import urllib
#import httplib
#from ftplib import FTP
#import socket
#import dbus
#import os


VERBOSE = True
UPDATE_LOG = "/var/log/lighttpd/nsg-upgrade.log"
LOCK_INSTALL_FILE = "/tmp/installationStart"
STATUS_FILE = "/tmp/firmware_update_status"


urls = (
    '/PY/CONFIG_EXPORT', 'ConfigExport',
    '/PY/CONFIG_IMPORT', 'ConfigImport',
    '/PY/LOG_EXPORT', 'LogExport',
    '/PY/IPTABLES_EXPORT', 'IpTablesExport',
    '/PY/IPTABLES_IMPORT', 'IpTablesImport',
    '/PY/EMULATION_EXPORT', 'EmulationExport',
    '/PY/EMULATION_IMPORT', 'EmulationImport',
    '/PY/EMULATION_GET_FILE', 'EmulationGetFile',
#    '/PY/FIRMWARE_LIST', 'FirmwareList',
    '/PY/FIRMWARE_UPDATE', 'FirmwareUpdate',
    '/PY/FIRMWARE_UPDATE_STATUS_QUERY', 'FirmwareUpdateStatusQuery',
    '/PY/FIRMWARE_UPDATE_LOG_QUERY', 'FirmwareUpdateLogQuery',
    '/PY/FIRMWARE_UPDATE_REBOOT', 'FirmwareUpdateReboot',
    '/PY/FIRMWARE_UPDATE_STATUS_INIT', 'FirmwareUpdateStatusInit',
    '/PY/CHANGE_PASS', 'ChangePass',
    '/PY/CHANGE_MYPASS', 'ChangeMyPass',
    '/PY/USER_ADD', 'UserAdd',
    '/PY/USER_DELETE', 'UserDelete',
    '/PY/USER_LIST', 'UserList',
    '/PY/REBOOT', 'Reboot',
    '/PY/CHECK_CONNECTION', 'CheckConnection',
    '/PY/GET_INFORMATION', 'GetInformation',
    '/PY/EXPORT_ISA_SESSIONS', 'ExportIsaSessions',
    '/PY/EXPORT_NGOD_SESSIONS', 'ExportNgodSessions',
    '/PY/EXPORT_ALARM_LOG', 'ExportAlarmLog',
    '/PY/EXPORT_ALARMS', 'ExportAlarms',
    '/PY/hello', 'Hello',
    '/PY/(.*)', 'Other'
)

def run_cmd ( cmd ):
    if VERBOSE:
        open( UPDATE_LOG, "a" ).write( "Running %s\n" % cmd )
    status = commands.getstatusoutput( cmd )
    if VERBOSE:
        open( UPDATE_LOG, "a" ).write( "%s\n" % status[1] )
    return status

############################ ConfigExport Class ######################################
class ConfigExport:

    def POST (self):
        export_file = '/tmp/sysconfig_export.zip'
        case = 'sysconfig'
        mycommand_sysconfig_export = "sudo /opt/harmonic/nsg/last_ver/scripts/export_files.sh " + case
        return doExportFile(mycommand_sysconfig_export, export_file, case)

############################ LogExport Class ######################################
class LogExport:

    def POST (self):
        export_file = '/tmp/logs_export.zip'
        case = 'logs'
        mycommand_logs_export = "sudo /opt/harmonic/nsg/last_ver/scripts/export_files.sh " + case
        return doExportFile(mycommand_logs_export, export_file, case)

############################ IpTablesExport Class ######################################
class IpTablesExport:

    def POST (self):
        export_file = '/tmp/iptables_export.zip'
        case = 'iptables'
        mycommand_iptables_export = "sudo /opt/harmonic/nsg/last_ver/scripts/export_files.sh " + case
        return doExportFile(mycommand_iptables_export, export_file, case)

############################ EmulationExport Class ######################################
class EmulationExport:

    def POST (self):
        user_data = web.input()
        if not 'FileName' in user_data:
            return web.internalerror(self)
        export_dir = "/etc/harmonic/nsg/cfg/"
        export_path = export_dir+user_data.FileName
        try:
            fin=open(export_path, 'r')
        except(IOError), e:
            return "ERROR can't open file"
        else:
            resp_file = fin.read()
            fin.close()
            web.header('Content-Type', 'text/xml')
            header_filename = 'attachment; filename='+user_data.FileName
            web.header('Content-Disposition', header_filename)
            return resp_file

############################ EmulationGetFile Class ######################################
class EmulationGetFile:

    def POST (self):
        user_data = web.input()
        if not 'FileName' in user_data:
            return web.internalerror(self)
        export_dir = "/etc/harmonic/nsg/cfg/"
        export_path = export_dir+user_data.FileName
        try:
            fin=open(export_path, 'r')
        except(IOError), e:
            return "ERROR can't open file"
        else:
            resp_file = fin.read()
            fin.close()
            web.header('Content-Type', 'text/xml')
            return resp_file
############################ ConfigImport Class ######################################
class ConfigImport:

    def POST (self):
        user_data = web.input(ImportFile={})
        if 'ImportFile' in user_data: # to check if the file-object is created
            mycommand_sysconfig_import = "sudo /opt/harmonic/nsg/last_ver/scripts/import_files.sh sysconfig"
            filedir = '/tmp/' # the directory to store the file in.
            filename='sysconfig_import.zip'
            myfile=user_data.ImportFile.file.read()
            return doImportFile(mycommand_sysconfig_import, filename, filedir, myfile)
        else:
            return "ERROR Importfile"

############################ IpTablesImport Class ######################################
class IpTablesImport:

    def POST (self):
        user_data = web.input(ImportFile={})
        if 'ImportFile' in user_data: # to check if the file-object is created
            mycommand_sysconfig_import = "sudo /opt/harmonic/nsg/last_ver/scripts/import_files.sh iptables"
            filedir = '/tmp/' # the directory to store the file in.
            filename='iptables_import.zip'
            myfile=user_data.ImportFile.file.read()
            return doImportFile(mycommand_sysconfig_import, filename, filedir, myfile)
        else:
            return "ERROR ImportFile"

############################ EmulationImport Class ######################################
class EmulationImport:

    def POST (self):
        user_data = web.input(ImportFile={})
        if not 'FileName' in user_data:
            return "ERROR FileName"
        if 'ImportFile' in user_data: # to check if the file-object is created
            export_dir = "/etc/harmonic/nsg/cfg/"
            export_path = export_dir + user_data.FileName
            tmpfiledir = '/tmp/'
            mycommand_emulation_import = "sudo /opt/harmonic/nsg/last_ver/scripts/emulation_import_files.sh " + export_dir + user_data.FileName
            myfile=user_data.ImportFile.file.read()
            return self.doEmulationImportFile(mycommand_emulation_import, export_path, tmpfiledir, myfile, user_data.FileName)
        else:
            return "ERROR ImportFile"

    def doEmulationImportFile (self, mycommand, export_path, tmpfiledir, myfile, filename):
        fout = file(tmpfiledir + filename,'w') # creates the file where the uploaded file should be stored
        fout.write(myfile) # writes the uploaded file to the newly created file.
        fout.close() # closes the file, upload complete.
        status = commands.getstatusoutput(mycommand)
        if os.WEXITSTATUS(status[0]) == 0:
            return "OK Import"
        else:
            return "ERROR Import " + status[1]

############################ FirmwareUpdate Class ######################################
class FirmwareUpdate:

    def POST (self):
        try:
            user_data = web.input()
            if not 'URL' in user_data:
                return web.internalerror(self)
            if not 'Version' in user_data:
                return web.internalerror(self)
            if not 'Reboot' in user_data:
                    return web.internalerror(self)
            if not user_data.URL:
                return "ERROR URL is missing"
            elif not user_data.Version:
                return "ERROR Version is missing"
            elif not user_data.Reboot:
                return "ERROR Reboot is missing"
            else:
                fd = os.open( LOCK_INSTALL_FILE, os.O_EXCL|os.O_CREAT )
                open( STATUS_FILE, "w" ).write("InProgress")
                status = self.doFirmwareUpdate(user_data.URL, user_data.Version, user_data.Reboot)
                return status
        except os.error, e:
            return "NotDeleteERROR Installation is already running"
        except:
            open( UPDATE_LOG, "a" ).write( traceback.format_exc() )
            open( STATUS_FILE, "w" ).write("Error")
            return "ERROR Upgrade failed"
        
    def doFirmwareUpdate(self, szURL, szVersion, szReboot):
        try:
            if os.path.exists(UPDATE_LOG):
                os.remove(UPDATE_LOG)
            upgrade_tarball = "nsg-upgrade.tar.gz"
            bsupgrade = 0;
            open( UPDATE_LOG, "a" ).write( "call to validConnection \n" )
            status = validConnection(szURL, szVersion, bsupgrade)
            if status != "OK":
                return status
            
            baseURL = re.sub(r'/[^/]+$', '', szURL)
            szVersion = szURL.split("/")[-1]
            open( UPDATE_LOG, "a" ).write( "got %s\n" % bsupgrade )
            tar = tarfile.open("/tmp/" + upgrade_tarball)
            tar.extractall(path="/tmp")
            tar.close()
            cmd = "sudo /tmp/nsg-upgrade/bootstrap_upgrade" + \
                (" %s %s %s %s" % (baseURL, szVersion, STATUS_FILE, szReboot))
            cmd += ( " >> %s 2>&1" % UPDATE_LOG )
            open( UPDATE_LOG, "a" ).write( "running %s\n" % cmd )
            status = commands.getstatusoutput(cmd)
            if status[0] != 0:
                raise Exception("Error: %s failed" % cmd)

        except Exception, e: 
            open( UPDATE_LOG, "a" ).write( traceback.format_exc() )
            raise

            
        if szReboot == "0":
            open( UPDATE_LOG, "a" ).write( "Manual Upgrade finished OK\n")
            open( STATUS_FILE, "w" ).write("Finished")
        else:
            open( UPDATE_LOG, "a" ).write( "Automatic Upgrade finished OK\n")
            open( STATUS_FILE, "w" ).write("AutoFinished")
        return "OK"

############################ CheckConnection Class ######################################

class CheckConnection:
    def POST (self):
        user_data = web.input()
        if not 'URL' in user_data:
            return web.internalerror(self)
        if not 'Version' in user_data:
            return web.internalerror(self)
        if not user_data.URL:
            return "ERROR URL is missing"
        if not user_data.Version:
            return "ERROR Version is missing"
        else:
            return self.doCheckConnection(user_data.URL, user_data.Version)

    def doCheckConnection(self, szURL, szVersion):
        #split_result = re.split('/', szURL)
        #szIP = split_result[2]
        # checking FTP connection
        #try: 
        #    ftp = FTP(szIP)
        #except Exception,e:
        #    return "ERROR %d %s" % (e[0] , e[1])
        #try: 
        #    ftp.login()
        #except Exception,e:
        #    return "ERROR %s" % (e[0])

        # checking HTTP connection
        bsupgrade = 0;
        if os.path.exists(LOCK_INSTALL_FILE):
            return "ERROR Installation is already running"
        return validConnection(szURL, szVersion, bsupgrade)


############################ FirmwareUpdateStatusQuery Class ######################################

class FirmwareUpdateStatusQuery:
    def POST (self):
        try:
            fin=open(STATUS_FILE, 'r')
        except(IOError), e:
            return "NotStarted"
        else:
            #response = fin.read()
            response = fin.readline()
            fin.close()
            return response

class FirmwareUpdateStatusInit:
    def POST (self):
        return removeInstallationFiles()


############################ FirmwareUpdateLogQuery Class ######################################

class FirmwareUpdateLogQuery:
    def POST (self):
        try:
            fin=open(UPDATE_LOG, 'r')
        except(IOError), e:
            return "ERROR can't open file"
        else:
            response =  fin.read()
            fin.close()
            return response

############################ FirmwareUpdateReboot Class ######################################

class FirmwareUpdateReboot:
    def POST (self):
        user_data = web.input()
        if not 'Confirm' in user_data:
            os.remove(LOCK_INSTALL_FILE)  
            return web.internalerror(self)
        if not user_data.Confirm:
            return "ERROR Confirm is missing"
        else:
            if not os.path.exists(STATUS_FILE):
                return "NotDeleteERROR Installation is not running"
            cmd = "/tmp/nsg-upgrade/sysroot/boot/nsg-upgrade/config_and_reboot"
            mycommand_upgrade_and_reboot = "sudo %s %s %s" % (cmd, user_data.Confirm, STATUS_FILE)
            mycommand_upgrade_and_reboot += ( " >> %s 2>&1" % UPDATE_LOG )
            status = commands.getstatusoutput(mycommand_upgrade_and_reboot)
            
            if user_data.Confirm == "0":
                if os.WEXITSTATUS(status[0]) == 0:
                    return removeInstallationFiles()
            if os.WEXITSTATUS(status[0]) == 0:
                #open( STATUS_FILE, "w" ).write("OK***")
                return "OK " + user_data.Confirm
            elif os.WEXITSTATUS(status[0]) == 2:
                return "NotDeleteERROR multiple calls to \"finalize and reboot\" process."
            else:
                return ("ERROR rebooting %d" % status[0])

############################ ChangePass Class ######################################
class ChangePass:

    def POST (self):
        user_data = web.input()
        if not 'Username' in user_data:
            return web.internalerror(self)
        if not 'Newpass' in user_data:
            return web.internalerror(self)
        if not user_data.Username:
            return "ERROR Username is missing"
        elif not user_data.Newpass:
            return "ERROR New Password is missing"
        else:
            return self.doChangePass(user_data.Username, urllib.unquote(user_data.Newpass))

    def doChangePass(self, Username, Newpass):
        if Username == "root" or Username == "nmsuser":
            return "ERROR request denied"
        else:
            mycommand_chg_pass = "sudo /opt/harmonic/nsg/last_ver/scripts/chg_pass.sh '" + Username + "' '" + Newpass + "'"
            status = commands.getstatusoutput(mycommand_chg_pass)
            if os.WEXITSTATUS(status[0]) == 0:
                return "OK Pass changed"
            else:
                return "ERROR passchange " + status[1]

############################ ChangeMyPass Class ######################################
class ChangeMyPass:

    def POST (self):
        user_data = web.input()
        if not 'Username' in user_data:
            return web.internalerror(self)
        if not 'Oldpass' in user_data:
            return web.internalerror(self)
        if not 'Newpass' in user_data:
            return web.internalerror(self)
        if not user_data.Username:
            return "ERROR Username is missing"
        elif not user_data.Oldpass:
            return "ERROR Old Password is missing"
        elif not user_data.Newpass:
            return "ERROR New Password is missing"
        else:
            return self.doChangeMyPass(user_data.Username, urllib.unquote(user_data.Oldpass), urllib.unquote(user_data.Newpass))

    def doChangeMyPass(self, Username, Oldpass, Newpass):
        if Username == "root" or Username == "nmsuser":
            return "ERROR request denied"
        else:
            mycommand_chg_mypass = "/opt/harmonic/nsg/last_ver/scripts/chg_mypass.sh '" + Username + "' '" + Newpass + "' '" + Oldpass + "'"
            status = commands.getstatusoutput(mycommand_chg_mypass)
            if os.WEXITSTATUS(status[0]) == 0:
                return "OK Pass changed"
            else:
                return "ERROR passchange " + status[1]

############################ UserAdd Class ######################################
class UserAdd:

    def POST (self):
        user_data = web.input()
        if not 'Username' in user_data:
            return web.internalerror(self)
        if not 'Newpass' in user_data:
            return web.internalerror(self)
        if not 'Group' in user_data:
            return web.internalerror(self)
        if not user_data.Username:
            return "ERROR Username is missing"
        elif not user_data.Newpass:
            return "ERROR New Password is missing"
        elif not user_data.Group:
                return "ERROR Group is missing"
        else:
            return self.doUserAdd(user_data.Username, user_data.Newpass, user_data.Group)

    def doUserAdd(self, Username, Newpass, Group):
        if Group == "nsgadmin" or Group == "nsgconfig" or Group == "nsgguest":
            mycommand_user_add = "sudo /opt/harmonic/nsg/last_ver/scripts/user_add.sh " + Username + " " + Newpass + " " + Group
            status = commands.getstatusoutput(mycommand_user_add)
            if os.WEXITSTATUS(status[0]) == 0:
                return "OK useradd"
            else:
                return "ERROR useradd " + status[1]
        else:
            return "ERROR request denied, can't add to this group"


############################ UserDelete Class ######################################
class UserDelete:

    def POST (self):
        user_data = web.input()
        if not 'Username' in user_data:
            return web.internalerror(self)
        if not user_data.Username:
            return "ERROR Username is missing"
        else:
            return self.doUserDelete(user_data.Username)

    def doUserDelete(self, Username):
        if Username == "root" or Username == "admin" or Username == "config" or Username == "guest" or Username == "nmsuser":
            return "ERROR request denied, can't delete fixed user"
        else:
            mycommand_user_delete = "sudo /opt/harmonic/nsg/last_ver/scripts/user_delete.sh " + Username
            status = commands.getstatusoutput(mycommand_user_delete)
            if os.WEXITSTATUS(status[0]) == 0:
                return "OK User deleted"
            else:
                return "ERROR userdelete " + status[1]

############################ UserList Class ######################################

class UserList:

    def POST (self):
        xmlresponse = "<USERS>\n"
        usergroup_array = {}
        group_file = open("/etc/group")
        lines = group_file.readlines()
        for l in lines:
                fields = string.split(l, ':')
                if re.match('^nsg', fields[0]):
                        usergroup_array[fields[2]] = fields[0]
        
        users_file = open("/etc/passwd")
        lines = users_file.readlines()
        for l in lines:
                fields = string.split(l, ':')
                try:
                        name = usergroup_array[fields[3]]
                except Exception,e:
                        continue
                #print "%-20s %s" % (fields[0], name)
                xmlresponse += ("<User Username=\"" + fields[0] + "\" Group=\"" + name + "\" />\n")
        xmlresponse += "</USERS>"
        users_file.close()
        group_file.close()
        return xmlresponse

############################ Reboot Class ######################################
class Reboot:

    def POST (self):
        return doReboot()

############################ Other Class ######################################
class Other:    
       
    def GET(self):
         return web.internalerror(self)

    def POST(self):
         return web.internalerror(self)

############################ Hello Class ######################################
class Hello: 
    def GET(self):
        name = "world"
        return self.DUMMY(name)

    def DUMMY (self, name):
        return "Hello, " + name + "!"

############################ GetInformation Class ######################################

class GetInformation:
    def POST (self):
        xmlStr = "<NSG><TSOUTCFG   Action=\"GET\" />" + \
"<DEVICECFG  Action=\"GET\" />" + \
"<UNITCFG    Action=\"GET\" />" + \
"<PIZZACFG   Action=\"GET\" />" + \
"<SLOTSCFG   Action=\"GET\" />" + \
"<IPINPCFG   Action=\"GET\" />" + \
"<SERVOUTCLASS Action=\"GET\" />" + \
"<TSOUTCLASS Action=\"GET\" />" + \
"<IPROUTECFG Action=\"GET\" />" + \
"<PIZZACLK Action=\"GET\" />" + \
"<SDVCFG Action=\"GET\" />" + \
"<PIDREMUXCFG Action=\"GET\" />" + \
"<DTICFG Action=\"GET\" />" + \
"<MOTMCCFG Action=\"GET\" />" + \
"<NGODSMCFG Action=\"GET\" />" + \
"<TWCSMCFG Action=\"GET\" />" + \
"<NGODCFG Action=\"GET\" />" + \
"<ERMCHCFG Action=\"GET\" />" +     \
"<CSD_License Action=\"3_Get_All\" />" + \
"<SNMPCFG Action=\"GET\" />" + \
"<HHPCFG Action=\"GET\" />" + \
"<PORTMIRRORCFG Action=\"GET\" />" + \
"<QAMMAPCFG Action=\"GET\" />" + \
"<STATUS     Action=\"GET\" />" + \
"<SESSION       Action=\"GET\" />" + \
"<USRLOG      Action=\"GET\" />" + \
"<IPINPCOUNTERS Action=\"GET\" />" + \
"<TRAFFIC       Action=\"GET\" />" + \
"<MOTERSCFG   Action=\"GET\" />" + \
"</NSG>"
        return GetXmlFromDevice(xmlStr)
       


############################ ExportIsaSessions Class ######################################

class ExportIsaSessions:

    def POST (self):
        xmlStr = "<NSG><TWCLIST   Action=\"GET\" />" + \
"</NSG>"
        return GetXmlFromDevice(xmlStr)
     

############################ ExportNgodSessions Class ######################################

class ExportNgodSessions:

    def POST (self):
        xmlStr = "<NSG><RTSPSESSIONCFG   Action=\"GET\" />" + \
"</NSG>"
        return GetXmlFromDevice(xmlStr)  
        
############################ ExportAlarmLog Class ######################################

class ExportAlarmLog:

    def POST (self):
        xmlStr = "<NSG><USRLOG   Action=\"GET\" />" + \
"</NSG>"
        return GetXmlFromDevice(xmlStr)  


############################ ExportAlarms Class ######################################

class ExportAlarms:

    def POST (self):
        xmlStr = "<NSG><STATUS   Action=\"GET\" />" + \
"</NSG>"
        return GetXmlFromDevice(xmlStr)  

#################### functions ######################

def doExportFile (mycommand, export_file, case):
    status = commands.getstatusoutput(mycommand)
    if os.WEXITSTATUS(status[0]) == 0:
        fin=open(export_file, 'r')            
        resp_file =  fin.read()
        fin.close()
        exported_filename = case+"_export.zip"
        web.header('Content-Type', 'application/zip')
        web.header('Content-Disposition', "attachment; filename="+exported_filename)
        return resp_file
    else:
        return "ERROR " + status[1]


def doImportFile (mycommand, filename, filedir, myfile):
    fout = file(filedir +'/'+ filename,'w') # creates the file where the uploaded file should be stored
    fout.write(myfile) # writes the uploaded file to the newly created file.
    fout.close() # closes the file, upload complete.
    status = commands.getstatusoutput(mycommand)
    if os.WEXITSTATUS(status[0]) == 0:
        return "OK Import"
    else:
        return "ERROR Import " + status[1]



def doReboot ():
    mycommand_reboot_import = "sudo /sbin/reboot"
    status = commands.getstatusoutput(mycommand_reboot_import)
    if os.WEXITSTATUS(status[0]) == 0:
        return "OK Reboot"
    else:
        return "ERROR Reboot " + status[1]


def GetXmlFromDevice (xmlStr):
    lengths = len(xmlStr)
    httpHeader="POST /BrowseConfig HTTP/1.1\r\nContent-Length:" + str(lengths) + "\r\nAuthorization: Digest username=\"root\"\r\n\r\n" + xmlStr
    defaultIP = '10.40.2.1'
    fileAns = tempfile.NamedTemporaryFile()
    fileName = fileAns.name
    command= "dbus-send --system --dest=com.harmonic.nsg.HttpInterface  --print-reply /com/harmonic/nsg/HttpInterface  com.harmonic.nsg.HttpInterface.HttpParser string:\'" + httpHeader + "\' string:\'" + defaultIP + "\'" + " 1>& " + fileName  
    status = os.system(command)
    ans = ""
    web.header('Content-Type', 'text/xml')
    web.header('Content-Disposition', "attachment; filename=")
    if status == 0:
        resp_file =  fileAns.read()
        fileAns.close()
        start_index= resp_file.find("<?xml")
        ans=resp_file[start_index:(len(resp_file)-2)]
    return ans


def removeInstallationFiles ():
    
    try:
        if os.path.exists(STATUS_FILE):
            os.remove(STATUS_FILE)
        
        if os.path.exists(LOCK_INSTALL_FILE):
            os.remove(LOCK_INSTALL_FILE)
            
    except(IOError), e:
        return "ERROR failed removing lock and status file"

def validConnection (szURL, szVersion, bsupgrade):
    
    try:
        upgrade_tarball = "nsg-upgrade.tar.gz"
        baseURL = re.sub(r'/[^/]+$', '', szURL)
        bootstrap_url = baseURL + "/nsg-upgrade/" + upgrade_tarball
        grabber = URLGrabber(timeout=30.0)
        bsupgrade = grabber.urlgrab( bootstrap_url, "/tmp/" + upgrade_tarball )
        
    except URLGrabError, e: 
          
        if e[0] == 4:
            aszHost = szURL.split("/")
            return "ERROR Connection check failed: Host %s is not responding" % (aszHost[2])
        elif e[0] == 14:
            return "ERROR Connection check failed: nsg-upgrade directory was not found in url %s" % szURL
        else:
            return "ERROR Checking Connection: %d %s" % (e[0] , e[1])
        return "ERROR " + e.strerror
    
    try:
        filehandler = grabber.urlopen(szURL + "/repodata/repomd.xml", copy_local=0, close_connection=1, keepalive=0, timeout=30.0, reget=None)
            
    except Exception, e: 
        
        if e[0] == 4:
            aszHost = szURL.split("/")
            return "ERROR Connection check failed: Host %s is not responding" % (aszHost[2])
        elif e[0] == 14:
            return "ERROR Connection check failed: Version %s was not found" % (szVersion)
        else:
            return "ERROR Checking Connection: %d %s" % (e[0] , e[1])

    return "OK"





if __name__ == "__main__":
    app = web.application(urls, globals())
    try:
        app.run()
    except:
        open( "/tmp/webapp_error.log", "w" ).write("Error")

 