# Lab 2 : CSE 508 Network Security


## Packet Sniffer
This is a basic packet sniffer made in accordance with lab 2 of CSE 508 Network Security Course. 

### Testing
For testing on standard port on different versions of TLS, use the below curl commands

```bash
# TLSv1.3 on Standard Port
curl -X G--tlsv1.3 --tls-max 1.3 --ciphers DEFAULT@SECLEVEL=0 -vI https://www.google.com

# TLSv1.2 on Standard Port
curl -X G--tlsv1.2 --tls-max 1.2 --ciphers DEFAULT@SECLEVEL=0 -vI https://www.google.com    

# TLSv1.1 on Standard Port
curl -X G--tlsv1.1 --tls-max 1.1 --ciphers DEFAULT@SECLEVEL=0 -vI https://www.google.com 

# TLSv1.0 on Standard Port
curl -X G--tlsv1.0 --tls-max 1.0 --ciphers DEFAULT@SECLEVEL=0 -vI https://www.google.com  

```

For testing on non-standard port of TLS, we used the https://portquiz.takao-tech.com website. 
This website is running on https and supports multiple non-standard ports like 9001, 8080, 80, 8, 666, etc.
I chose the non-standard port 9001 and different TLS versions for testing.
The following curl requests were made for testing tls requests on non-standard ports

```bash
# TLSv1.3 on Non-Standard Port
curl -X G--tlsv1.3 --tls-max 1.3 --ciphers DEFAULT@SECLEVEL=0 -vI https://portquiz.takao-tech.com:9001

# TLSv1.2 on Non-Standard Port
curl -X G--tlsv1.2 --tls-max 1.2 --ciphers DEFAULT@SECLEVEL=0 -vI https://portquiz.takao-tech.com:9001    

# TLSv1.1 on Non-Standard Port
curl -X G--tlsv1.1 --tls-max 1.1 --ciphers DEFAULT@SECLEVEL=0 -vI https://portquiz.takao-tech.com:9001  

# TLSv1.0 on Non-Standard Port
curl -X G--tlsv1.0 --tls-max 1.0 --ciphers DEFAULT@SECLEVEL=0 -vI https://portquiz.takao-tech.com:9001  

```

### Testing on Custom Port of HTTP
Testing on custom port can be done via website http://portquiz.net:8080/. 
This website is running on http and supports multiple ports like 8080, 80, 8, 666, etc. 
The following curl requests were made for testing http requests
```bash
# For port 80, standard port 
curl -X GET http://portquiz.net

# For port 8080, non-standard port testing
curl -X GET http://portquiz.net:8080

# For port 8, non-standard port testing
curl -X GET http://portquiz.net:8

# For port 666, non-standard port testing
curl -X GET http://portquiz.net:666
```

### Testing of TLS with custom HTTPS Server
This testing method is presented as an alternative for the above testing method for tls and is present in this documentation only for information purposes
This testing method must be used only if the above tls testing methods are absolutely not working. 
The file tls_server.py contains a quickly whipped up tls_server for testing purposes. 
You need to set up this server on a computer and then from a different computer on the same network,
you can call this server. Preferably both the computers should be linux. For testing, Macintosh operating
system was used. Below are the relevant steps

#### Step 1: Generate a Self-Signed SSL Certificate
First, use OpenSSL to generate a private key and a self-signed certificate. Open a terminal and run:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

#### Step 2: Run the python server
```bash
python3 tls_server.py
```

#### Step 3: Connect to the Server
For connecting to the server, go on a different computer on the same network, figure out the IP address
of the computer where the server is running and then replace localhost in the below line with the 
IP address of the target computer
```bash
openssl s_client -connect localhost:8443
```
