#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from Scyther import Scyther

# Test if backend works
s = Scyther.Scyther()
with open('ns3.spdl', 'r') as f:
    s.setInput(f.read())

print("Running verification...")
claims = s.verify()
print('Number of claims:', len(claims) if claims else 0)
if claims:
    for cl in claims:
        print(f'  Claim: {cl.id} - {cl.claimtype} - {cl.role}')
else:
    print("No claims returned!")
