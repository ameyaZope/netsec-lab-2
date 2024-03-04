# Lab 2 : CSE 508 Network Security


## Packet Sniffer
This is a basic packet sniffer made in accordance with lab 2 of CSE 508 Network Security Course. 

### Usage

#### TLSv1.3
```bash
curl -X G--tlsv1.3 --tls-max 1.3 --ciphers DEFAULT@SECLEVEL=0 -vI https://www.google.com       
```
#### TLSv1.2
```bash
curl -X G--tlsv1.2 --tls-max 1.2 --ciphers DEFAULT@SECLEVEL=0 -vI https://www.google.com    
```
#### TLSv1.1

```bash
curl -X G--tlsv1.1 --tls-max 1.1 --ciphers DEFAULT@SECLEVEL=0 -vI https://www.google.com  
```

#### TLSv1.0
```bash
curl -X G--tls-max 1.0 --ciphers DEFAULT@SECLEVEL=0 -vI https://www.google.com 
```