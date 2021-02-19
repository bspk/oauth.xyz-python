#!/usr/bin/env python3

import json
import urllib
import urllib.request
import jose.jws
import http.client
import time
import hashlib
import base64
import re

handler = urllib.request.HTTPHandler(debuglevel=10)
opener = urllib.request.build_opener(handler)
urllib.request.install_opener(opener)

keypair = {
    "kty": "EC",
    "d": "_L48N5D5pL6fsMAIOMqwrk_5trZLZ70N7_7wQ5fFqNU",
    "use": "sig",
    "crv": "P-256",
    "kid": "py-xyz",
    "x": "O0d8DpgwpcJjJNVy6wuQVn1dsFl29lOCav3OVxQinb0",
    "y": "DzPJO55dZtug6p9vhQNvkm-r-93W_4V3-K9tTcK6YX4",
    "alg": "ES256"
}

public_key = {
    "kty": "EC",
    "use": "sig",
    "crv": "P-256",
    "kid": "py-xyz",
    "x": "O0d8DpgwpcJjJNVy6wuQVn1dsFl29lOCav3OVxQinb0",
    "y": "DzPJO55dZtug6p9vhQNvkm-r-93W_4V3-K9tTcK6YX4",
    "alg": "ES256"
}

request = {
    "client": {
        "key": {
            "proof": "jwsd",
            "jwk": public_key
        },
        "display": {
            "name": "Python CLI"
        },
    },
    "access_token": {
        "label": "tok1",
        "access": [
            "foo", "bar", "baz"
        ]
    },
    "interact": {
        "redirect": True,
        "user_code": True
    }
}

asEndpoint = 'http://host.docker.internal:9834/api/as/transaction'

def requestSigned(url, body, at=None):
    jwsHeader = {
        "b64": False,
        "crit": [ "b64" ],
        "alg": keypair['alg'],
        "kid": keypair['kid'],
        "htu": url,
        "htm": "POST"
    }
    
    if at:
        m = hashlib.sha256()
        m.update(at.encode('utf-8'))
        h = m.digest()
        jwsHeader['at_hash'] = base64.urlsafe_b64encode(h[0:int(m.digest_size / 2)]).decode('utf-8').replace('=', '')

    print(jwsHeader)
    
    signed = jose.jws.sign(body, keypair, headers=jwsHeader, algorithm=keypair['alg'], unencoded=True)
    
    detached = re.sub('(^[^\.]+.).+(\.[^\.]+$)', '\\1\\2', signed) # safely cut out the payload
    
    print(detached)
    
    headers = {
        'Content-type': 'application/json',
        'Detached-JWS': detached
    }
    
    if at:
        headers['Authorization'] = 'GNAP ' + at
    
    req = urllib.request.Request(url, body, headers=headers)
    
    with urllib.request.urlopen(req) as response:
        return response.read()

def printResponse(t):
    if 'continue' in t:
        print('Continue:')
        print('   URI:       %s' % t['continue']['uri'])
        print('   Token:     %s' % t['continue']['access_token']['value'])

    if 'interact' in t:
        print('Interact:')
        if 'redirect' in t['interact']:
            print('   Redirect:  %s' % t['interact']['redirect'])
        if 'user_code' in t['interact']:
            print('   User Code: %s' % t['interact']['user_code']['code'])
            print('   URL:       %s' % t['interact']['user_code']['url'])

    if 'access_token' in t:
        if isinstance(t['access_token'], dict):
            print('Access Token:')
            print('  Value:      %s' % t['access_token']['value'])
        elif isinstance(t['access_token'], list):
            print('Access Tokens:')
            for at in t['access_token']:
                print('  Access Token:')
                print('    Value:    %s' % at['value'])
                print('    Label:    %s' % at['label'])
                



response = requestSigned(asEndpoint, json.dumps(request).encode('utf-8'))

print(response)

t = json.loads(response)

printResponse(t)

cont = t['continue']

while cont:
    print()
    input("Press Enter to poll, ^C to quit...")
    print()
    response = requestSigned(cont['uri'], ''.encode('utf-8'), cont['access_token']['value'])
    print(response)

    t = json.loads(response)

    printResponse(t)

    cont = t['continue']


