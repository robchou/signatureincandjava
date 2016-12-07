#!/bin/bash

echo 'data to sign' > data.txt

openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -nocrypt > private.der
