#!/bin/bash

# A quite simple script that generates maqueraded binaries.

cp /usr/bin/sleep /tmp/

cd  /tmp/

export PATH=.:$PATH

cp sleep [kworkerd]

# Test with different paths. 
./[kworkerd] 0.1
/tmp/[kworkerd] 0.1
[kworkerd] 0.1

cp sleep '  [kworkerd]'
'  [kworkerd]' 0.1

cp sleep 'file.txt '
'file.txt ' 0.1 &
