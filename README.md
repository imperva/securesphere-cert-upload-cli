
# SecureSphere Certification Upload CLI

This python cli utility helps to automate and manage the uploading of certificates into SecureSphere.  
The cli help menu provides 3 options of how to map which http service in the site tree to map the cert to, so it is possible to make this process dynamic as opposed to requiring each parameter to be specified at the time of upload

You will need to install both [Python3](https://www.python.org/downloads/) and
[pyOpenSSL](https://pyopenssl.org/en/stable/) on your system.

```
Install python3
```
then
```
pip3 install pyOpenSSL
```
You can generate a self-signed certificate using the following with [openssl](https://www.openssl.org/) for testing purposes:

Generate Self-signed Cert:
```
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt
```

There are three methods of uploading a certificate to map to the correct Service in hte Site Tree.  
1. Explicitly specify all parameters in commnad:
```
python3 CertUpload.py --site "ESXi Lab" --serverGroup "Server Group Name" --service "Apache Service" --sslKey www.superveda.com --priv /path/to/private/privateKey.key --pub /path/to/public/certificate.crt
```
    
2. Configure a lookup data set to map the common name of the cert to match a path of the site tree to the specific service (data set is expected to have three columns CommonName, SiteTreePath, SSLKey – if the data set specified in the CertUploadDefaults.py file does not exist, the user running the script will be prompted to create it): 
```
python3 CertUpload.py --method LDS --priv /path/to/private/privateKey.key --pub /path/to/public/certificate.crt
```

3. Look for a partial match of the whole common name to an application name that exists in the site tree: 
```
python3 CertUpload.py --method app --priv /path/to/private/privateKey.key --pub /path/to/public/certificate.crt
```
