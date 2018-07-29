#!/usr/bin/env python3
import CertUploadDefaults
import ss
import argparse
from OpenSSL import crypto

def OpenFile(fileName, readMode="rt"):
    with open(fileName, readMode) as f:
        fileTxt = f.read()
    f.closed

    return fileTxt

def FindByLookupDataSet(commonName,mxObj):
    LDSrecord = mxObj.RetrieveLookupDataSet(commonName, CertUploadDefaults.defLDS)

    if LDSrecord == "IMP-10094:Dataset not found":
        createNewLDS = input("The dataset named '"+CertUploadDefaults.defLDS+"' was not found. Would you like to create one? (Y/N): ")

        if createNewLDS.upper() == "Y":
            validate = "N"
            LDSdata = {}
            LDSdata["CommonName"] = commonName
            mxObj.AddLDS(CertUploadDefaults.defLDS,{"CommonName","SiteTreePath","SSLKey"})

            while(validate.upper() == "N"):
                LDSdata["SiteTreePath"] = input("Enter the site tree path to add to the '"+CertUploadDefaults.defLDS+"' dataset: ")
                LDSdata["SSLKey"] = input("Enter the ssl key to add to the '"+CertUploadDefaults.defLDS+"' dataset: ")

                if LDSdata["SiteTreePath"] == "" or LDSdata["SSLKey"] == "":
                    validate = "N"
                    print("Please make sure to provide a value for site tree path and ssl key.")
                else:
                    validate = input("A record will be added to the '"+CertUploadDefaults.defLDS+"' data set with the following values.\n\tCommon Name: " + commonName + "\n\tSite Tree Path: " + LDSdata["SiteTreePath"] + "\n\tSSL Key: " + LDSdata["SSLKey"] + "\n\t\n\n\tIs that correct? (Y/N): ")

                if(validate.upper() == "Y"):
                    mxObj.AddLDSData(CertUploadDefaults.defLDS, [LDSdata])

        LDSrecord = mxObj.RetrieveLookupDataSet(commonName, CertUploadDefaults.defLDS)

    return LDSrecord

def FindByAppName(commonName, mxObj):
    matchingAppFound = False
    print(commonName)
    sites = mxObj.GetAllSites()
    for site in sites:
        print(site)
        serverGroups = mxObj.GetAllServerGroups(site)
        for serverGroup in serverGroups:
            webServices = mxObj.GetAllWebServices(site,serverGroup)
            for webService in webServices:
                webApps = mxObj.GetAllWebApplications(site,serverGroup,webService)
                for webApp in webApps:
                    if commonName.upper() in webApp.upper():
                        matchingAppFound = True
                        break
                if matchingAppFound:
                    return([site,serverGroup,webService])
    return([])

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,description="This script uploads SSL Certificates to Imperva SecureSphere. In order for it to run properly it must be in the same directory as ss.py and certUploadDefaults.py. To reduce the number of command line parameters that are necessary, utilize the default parameters in certUploadDefaults.py. The examples in this description will assume all default values have been filled out. \n\nThis script is capable of uploading scripts three different ways:\n\n1) Explicitly passing the site name, server group name, service name, and sslkey to which the cert should be applied.\n\nEx: CertUpload.py --site siteName --serverGroup serverGroupName --service serviceName --sslkey sslkeyName --pub PEMFilePublicKey --priv PEMFilePrivateKey \n\n2) Utilizing a lookup data set, the name of which is specified by the defLDS parameter in the CertUploadDefaults.py file. In this case the script will match the common name associated with the certificate to the the CommonName column of the lookup data set. It will then add the certificate to the service specified in the SiteTreePath column of the lookup data set with the SSL key specified in the SSLKey column of the lookup data set. If no lookup data set matching the name specified has been created, the script will prompt the user to create a new lookup data set.\n\nEx: CertUpload.py --pub PEMFilePublicKey --priv PEMFilePrivateKey --method LDS\n\n3) Lastly, the script will iterate through all sites, server groups, services, and applications looking for an application name that is a partial or complete match to the common name associated with the certificate. It will then add the certificate to that application with the common name as the SSL Key.\n\n Ex: CertUpload.py --pub PEMFilePublicKey --priv PEMFilePrivateKey --method App")

#Setup Command Line Arguments
parser.add_argument("--port",default=CertUploadDefaults.defPort, help="Use this parameter if the default port for your MX GUI Interface is not 8083. A new default can be specified in CertUploadDefaults.py.")
parser.add_argument("--address", default=CertUploadDefaults.defMXAddress, help="REQUIRED. SecureSphere IP address. If you do not want to supply this as a command line argument, then edit CertUploadDefaults.py file. Set <defMxAddress> = Your MX IP.")
parser.add_argument("-u","--user", default=CertUploadDefaults.defMXUser, help="REQUIRED. SecureSphere user account. If you do not want to supply this as a command line argument, then edit CertUploadDefaults.py file. Set <defMXUser> = your mx username.")
parser.add_argument("--upass", default=CertUploadDefaults.defMXPass, help="REQUIRED. SecureSpheere user password. If you do not want to supply this as a command line argument, then edit CertUploadDefaults.py file. Set <defMXPass> = your mx  password.")
parser.add_argument("--priv", help="Path to PEM private key certificate file. If PEM format is used, public key must also be supplied using the [-p, --pub] argument.")
parser.add_argument("--pub", help="Path to PEM public key certificate file. If PEM format is used, private key must also be supplied using the [-x, --priv] argument.")
parser.add_argument("--hsm", action="store_true", help="Use this argument to indicate if this SSL certificate is used by HSM.")
parser.add_argument("--delete", action="store_true", help="Use this option this to replace a certificate in an existing SSL Key record.")
parser.add_argument("--fpass", help="File password for pkcs12 format")
parser.add_argument("--file", help="Path to pkcs12 file, if pkcs format is to be used. Cannot be used in conjunction with [-x, --priv] and/or [-p,--pub] arguments.")
parser.add_argument("--site", default=CertUploadDefaults.defSite, help="REQUIRED when not using --method App or --method LDS options. Name of SecureSphere site, to which certificate will be uploaded. If you do not want to submit this as a command line argument, edit CertUploadDefaults.py file. Set <defSite> = Site Name.")
parser.add_argument("--serverGroup", default=CertUploadDefaults.defServerGroup, help="REQUIRED when not using --method App or --method LDS options. Name of the SecureSphere server group, to which the certificate will be uploaded. If you do not want to submit this as a command line argument, edit CertUploadDefaults.py file. Set <defServerGroup> = Server Group Name.")
parser.add_argument("--service", default=CertUploadDefaults.defService, help="REQUIRED when not using --method App or --method LDS options. Name of the SecureSphere service, to which the certificate will be uploaded. If you do not want to submit this as a command line argument, edit CertUploadDefaults.py file. Set <defService> = Service Name.")
parser.add_argument("--sslKey", help="REQUIRED when not using --method LDS or --method App. Name of the SecureSphere SSL key, to which the certificate will be uploaded.If the SSL Key name does not exist, it will be created. If you want to replace the certificate in an existing SSL Key record, be sure to also use the [-d, --delete] option.")
parser.add_argument("--method", default="", help="OPTIONAL: Used to determine where to add certificates. 'App' will determine where to add the specified certificate by doing a partial match of the common name associated with your certificate to the Application names in your site tree. 'LDS' will determine where to add your certificate by looking up the common name associated with your certificate in the 'CommonName' column of lookup data set specified in the default configuration file (" + CertUploadDefaults.defLDS + "). The cert will be added to the site tree path specified in the SiteTreePath column of the corresponding record.")

args = parser.parse_args()

MX = ss.SecureSphere(args.address,args.port,args.user,args.upass)
if not MX.login():
    raise ConnectionError("There was an error connecting to SecureSphere API. Please check the IP address, port, user name, and a passwords")

response = "Success"

if args.pub is None:
    p12 = crypto.load_pkcs12(OpenFile(args.file,"rb"),args.fpass)
    privCertTxt = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
    pubCertTxt = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())
    privCertTxt = privCertTxt.decode("utf-8")
    pubCertTxt = pubCertTxt.decode("utf-8")
    p12 = None
else:
    pubCertTxt = OpenFile(args.pub)
    privCertTxt = OpenFile(args.priv)

pem = crypto.load_certificate(crypto.FILETYPE_PEM, pubCertTxt)

if args.method.upper() == "LDS":
    LDSresults = FindByLookupDataSet(pem.get_subject().CN,MX)
    pathParts = LDSresults["SiteTreePath"].split("/")
    if len(pathParts) != 3:
        response = "The supplied by the lookup data set - " + siteTreePath + " - was not valid."

    args.site = pathParts[0]
    args.serverGroup = pathParts[1]
    args.service = pathParts[2]
    args.sslKey = LDSresults["SSLKey"]

elif args.method.upper() == "APP":
    results = FindByAppName(pem.get_subject().CN, MX)
    if len(results) == 0:
        response = "Could not find any application names containing a partial match to the certificate common name: " + pem.get_subject().CN + "."
    else:
        args.site = results[0]
        args.serverGroup = results[1]
        args.service = results[2]
        args.sslKey = pem.get_subject().CN

if args.delete:
    response = MX.RemoveSSLCertificate(args.site, args.serverGroup, args.service, args.sslKey)
    if response != "Success":
        print("SecureSphere API was unable to delete the existing SSL Certificate. Failed with response: " + response)

if response == "Success":
    response = MX.UploadPEMSSLCertificates(args.site, args.serverGroup, args.service, args.sslKey,pubCertTxt,privCertTxt,"true" if args.hsm else "false")

if response != "Success":
    print("SecureSphere API was unable to add the Certificate to location specificed. Failed with response: " + response)
else:
    print("SecureSphere API successfully added the Certificate with SSL Key name '" + args.sslKey + "' to " + args.site + "->" + args.serverGroup + "->" + args.service)

MX.logout()
