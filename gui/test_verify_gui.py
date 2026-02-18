#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from Scyther import Scyther

# Read the file
with open('ns3.spdl', 'r') as f:
    spdl = f.read()

# Construct options like Settings window would for "verify" mode
# Based on Settingswindow.ScytherArguments()
mode = "verify"
maxruns = 5
match = 0
prune = 2
maxattacks = 10

options = f"--max-runs={maxruns} --match={match} --prune={prune}"
if maxattacks != 0:
    options += f" --max-attacks={maxattacks}"

# Note: "verify" mode doesn't add any additional flags

print(f"Mode: {mode}")
print(f"Options: '{options}'")
print()

# Run Scyther
scyther = Scyther.Scyther()
scyther.options = options
scyther.setInput(spdl)

print("Running Scyther verification...")
try:
    claims = scyther.verify()
    print(f"Verification complete!")
    print(f"Error count: {scyther.errorcount}")
    print(f"Claims returned: {claims}")
    if claims:
        print(f"Number of claims: {len(claims)}")
        for cl in claims:
            print(f"  - Claim {cl.id}: {cl.protocol}/{cl.role} - {cl.claimtype}")
    else:
        print("Claims is None or empty!")
except Exception as e:
    print(f"Exception during verify: {e}")
    import traceback
    traceback.print_exc()
