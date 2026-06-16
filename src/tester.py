
#Test document for different libraries

#WHOIS alternatives

#Whodap
from whodap import lookup_domain

def main1():
    result = lookup_domain("google", "com")
    print(result)

#Requests
import requests

def main2():
    r = requests.get(
    "https://rdap.org/domain/google.com",
    timeout=10
    )

    data = r.json()
    print(data)

#WHOIS
import whois

def main3():
    whoisinfo = whois.whois("chirpbooks.com")
    print(whoisinfo)

if __name__ == "__main__":
    main3()