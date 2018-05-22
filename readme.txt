Install python3

then
pip3 install pyOpenSSL

Generate Self-signed Cert
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt

Specify everything: 
python3 CertUpload.py --site "ESXi Lab" --serverGroup "Server Group Name" --service "Apache Service" --sslKey www.superveda.com --priv /path/to/private/privateKey.key --pub /path/to/public/certificate.crt
    
Lookup data set (data set is expected to have three columns CommonName, SiteTreePath, SSLKey – if the data set specified in the CertUploadDefaults.py file does not exist, the user running the script will be prompted to create it): 
python3 CertUpload.py --method LDS --priv /path/to/private/privateKey.key --pub /path/to/public/certificate.crt

Look for a partial match of the whole common name to an application name that exists in the site tree: 
python3 CertUpload.py --method app --priv /path/to/private/privateKey.key --pub /path/to/public/certificate.crt

