# Imperva.py
import urllib.request
import urllib.error
import urllib.parse
import urllib
import ssl
import base64
import json


class DBService:

    def __init__(self,Name="",Ports=[],DefaultApp="",Mappings=[],TextReplacements=[]):
        self.Name = Name
        self.Ports = Ports
        self.DefaultApp = DefaultApp
        self.Mappings = Mappings
        self.TextReplacements = TextReplacements

    def SetName(self,NewName):
        self.Name = NewName

    def GetName(self):
        return self.Name

    def GetPorts(self):
        return self.Ports

    def AddPort(self,Port):
        self.Ports.append(Port)

    def ClearPorts(self):
        self.Ports = []

    def SetDefaultApp(self,App):
        self.DefaultApp = App

    def GetDefaultApp(self):
        return self.DefaultApp

    def ClearMappings(self):
        self.Mappings = []

    def AddMapping(self,DB,Schema,App):
        self.Mappings.append({"database":DB,"schema":Schema,"App":App})

    def GetMappings(self):
        return self.Mappings

    def ClearTextReplacements(self):
        self.TextReplacements = []

    def AddTextReplacement(self,Location,Pattern,Replacement,Advanced):
        if Location==0: Loc = "NormalizedQuery"
        if Location==1: Loc = "UserName"
        if Location==2: Loc = "ApplicationUserName"
        self.TextReplacements.append({"location":Loc,"replacement":Replacement,"pattern":Pattern,"advanced":Advanced})

    def GetTextReplacements(self):
        return self.TextReplacements
        


class SecureSphere:

    def __init__(self,IP,Port,User,Password,Version="v1"):
        self.IP = ""
        self.Port = Port
        self.IsAuthenticated = False
        self.AuthToken = ""
        self.BaseURL = "https://" + IP + ":" + Port + "/SecureSphere/api/" + Version
        self.User = User
        self.Password = Password
        self.Error = False
        self.ResponseCode = None
        self.ResponseString = None

   

    def login(self):
        Request = urllib.request.Request(url=self.BaseURL+"/auth/session")
        AuthString = self.User+":"+self.Password
        Request.add_header("Authorization","Basic " + base64.b64encode(AuthString.encode("utf-8")).decode("utf-8"))
        Request.method="POST"
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

        try:
            Response = urllib.request.urlopen(Request, context=gcontext)
        except urllib.error.HTTPError as HTTPException:
            # we should only see 401 here for invalid creds, so handle it nicely
            # otherwise re-raise the exception because it means something is wrong
            self.Error = True
            self.ResponseCode = HTTPException.code
            self.ResponseString = HTTPException.reason
            if HTTPException.code == 401:
                return False
            else:
                raise
        else:
            self.ResponseCode = Response.getcode()
            self.ResponseString = Response.reason
            if Response.getcode() == 200:
                self.AuthToken = json.loads(Response.read().decode("utf-8"))["session-id"]
                self.IsAuthenticated = True
                self.Error = False
                return True
            else:
                self.Error = True
                return False

    def logout(self):
        Request = urllib.request.Request(url=self.BaseURL+"/auth/session")
        Request.add_header("Cookie",self.AuthToken)
        Request.method="DELETE"
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        try:
            Response = urllib.request.urlopen(Request, context=gcontext)
        except urllib.error.HTTPError as HTTPException:
            # we should only see 401 here for invalid creds, so handle it nicely
            # otherwise re-raise the exception because it means something is wrong
            self.Error = True
            self.ResponseCode = HTTPException.code
            self.ResponseString = HTTPException.reason
            if HTTPException.code == 401:
                return False
            else:
                raise
        else:
            self.ResponseCode = Response.getcode()
            self.ResponseString = Response.reason
            if Response.getcode() == 200:
                self.AuthToken = ""
                self.IsAuthenticated = False
                self.Error = False
                return True
            else:
                self.Error = True
                return False


    def SendRequest(self,URL,method,data=None,ContentType=None):
        # setup
        Request = urllib.request.Request(url=self.BaseURL+urllib.parse.quote(URL,"/?=&"))
        Request.add_header("Cookie",self.AuthToken)
        Request.method=method
        if ContentType != None:
            Request.add_header("Content-Type",ContentType)
        if data == None:
            content = None
        else:
            content = data.encode("utf-8")
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        # execute
        try:
            Response = urllib.request.urlopen(Request,content, context=gcontext)
        except urllib.error.HTTPError as HTTPException:

            # populate the internal error facility
            self.ResponseCode = HTTPException.code
            self.ResponseString = HTTPException.reason
            self.Error = True

            # If there's JSON data, decode it and load into a string
            ResponseData = HTTPException.read().decode("utf-8")
            if len(ResponseData) > 0:
                ResponseJSON = json.loads(ResponseData)
            else:
                ResponseJSON = None

            # Handle nicely the errors we know about, reraise at the end otherwise
            if HTTPException.code == 401:
                return None
            elif HTTPException.code == 406:
                return ResponseJSON
            else:
                raise
        else:

            # populate the internal response facility
            self.ResponseCode = Response.getcode()
            self.ResponseString = Response.reason
            
            # if there's JSON data, decode it and load into a string
            ResponseData = Response.read().decode("utf-8")
            if len(ResponseData) > 0:
                ResponseJSON = json.loads(ResponseData)
            else:
                ResponseJSON = None

            # 200 is our only successful error code
            if Response.getcode() == 200:
                self.Error = False
                return ResponseJSON
            else:
                self.Error = True
                return ResponseJSON       


    def FormatJSONError(self, JSON):
        if JSON:
            return JSON["errors"][0]["error-code"] + ":" + JSON["errors"][0]["description"]

    def DeleteObject(self,Path):
        ResponseJSON = self.SendRequest(Path,"DELETE")
        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            return "Success"

    def CreateObject(self,Path,Data=None):
        if Data:
            ResponseJSON = self.SendRequest(Path,"POST",json.dumps(Data),"application/json")
        else:
            ResponseJSON = self.SendRequest(Path,"POST")
        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            return "Success"
        
    def GetObject(self,Path):
        Data = self.SendRequest(Path,"GET")
#        print(Path,Key,Data)
        if self.Error:
            return None
        else:
            return Data
        

# functions above are helpers and non-standard
# functions below are standard API



    def SetLogLevel(self,Level):
        # Create the JSON input
        JSON = {"type":"OpenAPI","level":Level.capitalize()}
        ResponseJSON = self.SendRequest("/administration/log/level","PUT",json.dumps(JSON),"application/json")
        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            return "Success"

    def SetAPIMode(self,Mode):
        # Create the JSON input
        JSON = {"mode":Mode.capitalize()}
        ResponseJSON = self.SendRequest("/administration/strict","PUT",json.dumps(JSON),"application/json")
        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            return "Success"

    def UpdateSite(self,OldName,NewName):
        JSON = {"name":NewName}
        ResponseJSON = self.SendRequest("/conf/sites/"+OldName,"PUT",json.dumps(JSON),"application/json")
        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            return "Success"

    def UpdateServerGroup(self,Site,OldName,NewName):
        JSON = {"name":NewName}
        ResponseJSON = self.SendRequest("/conf/serverGroups/"+Site+"/"+OldName,"PUT",json.dumps(JSON),"application/json")
        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            return "Success"

    def RemoveSSLCertificate(self, Site, ServerGroup, ServiceName, SSLKeyName):
        ResponseJSON = self.SendRequest("/conf/webServices/"+Site+"/"+ServerGroup+"/"+ServiceName+"/sslCertificates/"+SSLKeyName,"DELETE","application/json")
        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            return "Success"

    def UploadPKCSSSLCertificates(self,Site,ServerGroup,ServiceName,SSLKeyName, certFile, certPass, usedByHSM):
        JSON = {
            "format":"pkcs12",
            "password":certPass,
            "pkcs12file":certFile,
            "hsm":usedByHSM
        }
        ResponseJSON = self.SendRequest("/conf/webServices/"+Site+"/"+ServerGroup+"/"+ServiceName+"/sslCertificates/"+SSLKeyName,"POST",json.dumps(JSON),"application/json")
        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            return "Success"

    def UploadPEMSSLCertificates(self,Site,ServerGroup,ServiceName,SSLKeyName, publicKey, privateKey,usedByHSM):
        JSON = {
            "format":"pem",
            "certificate":publicKey,
            "private":privateKey,
            "hsm":usedByHSM
        }
        ResponseJSON = self.SendRequest("/conf/webServices/"+Site+"/"+ServerGroup+"/"+ServiceName+"/sslCertificates/"+SSLKeyName,"POST",json.dumps(JSON),"application/json")

        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            return "Success"

    def RetrieveLookupDataSet(self, commonName, ldsName):
        ResponseJSON = self.SendRequest("/conf/dataSets/"+ldsName+"/data","GET","{}","application/json")

        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            siteTreePath = "No entry matching common name, \""+commonName+"\" found."
            returnRec = {}
            for record in ResponseJSON["records"]:
                if record["CommonName"] == commonName:
                   returnRec = record
                   break;
            return returnRec

    def AddLDS(self, ldsName, columnNames):
        jsonDataList = []

        for idx, columnName in enumerate(columnNames):
            jsonDataList.append({"name":columnName,"key":True if idx == 0 else False})

        JSON = {
            "dataset-name":ldsName,
            "columns":jsonDataList
        }

        ResponseJSON = self.SendRequest("/conf/dataSets/createDataset?caseSensitive=false","POST",json.dumps(JSON),"application/json")

        if self.Error:
            return self.FormatJSONError(ResponseJSON)
        else:
            return "Success"


    def AddLDSData(self, ldsName, dataToAdd):
        JSON = {
            "action" : "add",
            "records" : dataToAdd
        }

        ResponseJSON = self.SendRequest("/conf/dataSets/"+ldsName+"/data","PUT",json.dumps(JSON),"application/json")

        if self.Error:
            return self.FormatJSONError(Response.JSON)
        else:
            return "Success"


    def DelSite(self,Site):
        return self.DeleteObject("/conf/sites/"+Site)

    def DelServerGroup(self,Site,ServerGroup):
        return self.DeleteObject("/conf/serverGroups/"+Site+"/"+ServerGroup)

    def DelDBService(self,Site,ServerGroup,Service):
        return self.DeleteObject("/conf/dbServices/"+Site+"/"+ServerGroup+"/"+Service)

    def DelDBApplication(self,Site,ServerGroup,Service,Application):
        return self.DeleteObject("/conf/dbApplications/"+Site+"/"+ServerGroup+"/"+Service+"/"+Application)

    def DelProtectedIP(self,Site,ServerGroup,IP,Gateway):
        return self.DeleteObject("/conf/serverGroups/"+Site+"/"+ServerGroup+"/"+IP+"?gatewayGroup="+Gateway)

    def RemDBServiceDataInterface(self,Site,ServerGroup,Service,Agent,ID):
        return self.DeleteObject("/conf/dbServices/"+Site+"/"+ServerGroup+"/"+Service+"/agents/"+Agent+"/dataInterfaces/"+ID)
		
    def DelAgentTags(self,Agent):
        return self.DeleteObject("/conf/agents/"+Agent+"/tags/")
		
    def DelAgentTag(self,Agent,Tag):
        return self.DeleteObject("/conf/agents/"+Agent+"/tags/"+Tag)

    def DelTag(self,Tag,Remove="false",Delete="true"):
        return self.DeleteObject("/conf/tags/"+Tag+"?remove="+Remove+"&delete="+Delete)

    def RemDBServiceSecPol(self,Site,ServerGroup,Service,Policy):
        return self.DeleteObject("/conf/dbServices/"+Site+"/"+ServerGroup+"/"+Service+"/dbSecurityPolicies/"+Policy)
		
    def RemDBAppSecPol(self,Site,ServerGroup,Service,Application,Policy):
        return self.DeleteObject("/conf/dbApplications/"+Site+"/"+ServerGroup+"/"+Service+"/"+Application+"/dbSecurityPolicies/"+Policy)
		
    def RemAppGroupDBSecPol(self,AppGroup,Policy):
        return self.DeleteObject("/conf/applicationGroups/"+AppGroup+"/dbSecurityPolicies/"+Policy)
		
    def RemDBServiceAuditPol(self,Site,ServerGroup,Service,Policy):
        return self.DeleteObject("/conf/dbServices/"+Site+"/"+ServerGroup+"/"+Service+"/auditPolicies/"+Policy)
		
    def RemDBAppSecPol(self,Site,ServerGroup,Service,Application,Policy):
        return self.DeleteObject("/conf/dbApplications/"+Site+"/"+ServerGroup+"/"+Service+"/"+Application+"/auditPolicies/"+Policy)
		
    def RemAppGroupDBAuditPol(self,AppGroup,Policy):
        return self.DeleteObject("/conf/applicationGroups/"+AppGroup+"/auditPolicies/"+Policy)
		
    def ClearLDS(self,LDS):
        return self.DeleteObject("/conf/dataSets/"+LDS+"/data")
		
    def DelAppGroup(self,AppGroup):
        return self.DeleteObject("/conf/applicationGroups/"+AppGroup)
		
    def RemAppGroupApp(self,AppGroup,Site,ServerGroup,Service,App):
        return self.DeleteObject("/conf/applicationGroups/"+AppGroup+"/applications/"+Site+"/"+ServerGroup+"/"+Service+"/"+App)
		
    def CreateSite(self,Site):
        return self.CreateObject("/conf/sites/"+Site)

    def CreateServerGroup(self,Site,SG):
        return self.CreateObject("/conf/serverGroups/"+Site+"/"+SG)

    def CreateDBService(self,Site,SG,Service,Type,Ports=None):
        # unfortunately type is case sensitive
        # ridiculous
        if Type.lower() == "oracle": Type = "Oracle"
        if Type.lower() == "mssql": Type = "MsSql"
        if Type.lower() == "sybase": Type = "Sybase"
        if Type.lower() == "db2": Type = "Db2"
        if Type.lower() == "informix": Type = "Informix"
        if Type.lower() == "teradata": Type = "Teradata"
        if Type.lower() == "sybaseiq": Type = "SybaseIQ"
        if Type.lower() == "mysql": Type = "MySql"
        if Type.lower() == "netezza": Type = "Netezza"
        if Type.lower() == "progress": Type = "Progress"
        if Type.lower() == "cache": Type = "Cache"
        if Ports:
            JSON = {"db-service-type":Type,"ports":Ports}
        else:
            JSON = {"db-service-type":Type}
        return self.CreateObject("/conf/dbServices/"+Site+"/"+SG+"/"+Service,JSON)
		
    def CreateDBApplication(self,Site,SG,Service,App):
        return self.CreateObject("/conf/dbApplications/"+Site+"/"+SG+"/"+Service+"/"+App)

    def CreateProtectedIP(self,Site,SG,IP,Gateway,Comment=None):
        if Comment:
            return self.CreateObject("/conf/serverGroups/"+Site+"/"+SG+"/protectedIPs/"+IP+"?gatewayGroup="+Gateway, {"comment":Comment})
        else:
            return self.CreateObject("/conf/serverGroups/"+Site+"/"+SG+"/protectedIPs/"+IP+"?gatewayGroup="+Gateway, {"comment":""})
        
    def AddDBServiceDataInterface(self,Site,SG,Service,Agent,ID):
        return self.CreateObject("/conf/dbServices/"+Site+"/"+SG+"/"+Service+"/agents/"+Agent+"/dataInterfaces/"+ID)

    def ReplaceAgentTags(self,Agent,Tags):
        return self.CreateObject("/conf/agents/"+Agent+"/tags/", {"tags" : Tags})

    def AddAgentTag(self,Agent,Tag):
        return self.CreateObject("/conf/agents/"+Agent+"/tags/"+Tag)
    
    def CreateTag(self,Tag):
        return self.CreateObject("/conf/tags/"+Tag)

    def ApplyDBServiceSecPol(self,Site,SG,Service,Policy):
        return self.CreateObject("/conf/dbServices/"+Site+"/"+SG+"/"+Service+"/dbSecurityPolicies/"+Policy)

    def ApplyDBAppSecPol(self,Site,SG,Service,App,Policy):
        return self.CreateObject("/conf/dbApplications/"+Site+"/"+SG+"/"+Service+"/"+App+"/dbSecurityPolicies/"+Policy)

    def ApplyAppGroupDBSecPol(self,AppGroup,Policy):
        return self.CreateObject("/conf/applicationGroups/"+AppGroup+"/dbSecurityPolicies/"+Policy)

    def ApplyDBServiceAuditPol(self,Site,SG,Service,Policy):
        return self.CreateObject("/conf/dbServices/"+Site+"/"+SG+"/"+Service+"/auditPolicies/"+Policy)

    def ApplyDBAppAuditPol(self,Site,SG,Service,App,Policy):
        return self.CreateObject("/conf/dbApplications/"+Site+"/"+SG+"/"+Service+"/"+App+"/auditPolicies/"+Policy)

    def ApplyAppGroupDBAuditPol(self,AppGroup,Policy):
        return self.CreateObject("/conf/applicationGroups/"+AppGroup+"/auditPolicies/"+Policy)

    def ReplaceLDSData(self,LDS,JSON):
        return self.CreateObject("/conf/dataSets/"+LDS+"/data",JSON)

    def CreateAppGroup(self,Parent,AppGroup):
        if Parent == None:
            return self.CreateObject("/conf/applicationGroups/"+AppGroup)
        else:
            return self.CreateObject("/conf/applicationGroups/"+Parent+"/applicationGroups/"+AppGroup)

    def AddAppGroupApp(self,AppGroup,Site,SG,Service,App):
        return self.CreateObject("/conf/applicationGroups/"+AppGroup+"/applications/"+Site+"/"+SG+"/"+Service+"/"+App)

    def GetVersion(self):
        return self.GetObject("/administration/version")["serverVersion"]

    def GetAllSites(self):
        return self.GetObject("/conf/sites")["sites"]
   
    def GetAllServerGroups(self,Site):
        return self.GetObject("/conf/serverGroups/"+Site)["server-groups"]

    def GetAllWebServices(self,Site,ServerGroup):
        return self.GetObject("/conf/webServices/"+Site+"/"+ServerGroup)["web-services"]

    def GetAllWebApplications(self,Site,ServerGroup,WebService):
        return self.GetObject("/conf/webApplications/"+Site+"/"+ServerGroup+"/"+WebService)["webApplications"]

    def GetDBService(self,Site,SG,Service):
        JSON = self.GetObject("/conf/dbServices/"+Site+"/"+SG+"/"+Service)
        DBS = DBService(JSON["name"],JSON["ports"],JSON["default-application"],JSON["db-mappings"],JSON["text-replacement"])
        return DBS

    
