"""Reject missing checks, incomplete proofs, native-evaluation or new axioms."""
import re
import sys
from pathlib import Path
text=Path(sys.argv[1]).read_text()
expected={'completeness','differenceEquations','responseDifferenceNonzero','extraction',
 'branchSpecialSoundness','orSpecialSoundness','falseStatementUniqueChallenge',
 'simulatorAccepts','maskEquiv','betaEquiv','printedBetaIsIdentity'}
allowed={'propext','Classical.choice','Quot.sound'}
found={}
pattern=r"'SignatureGate\.(\w+)' (?:depends on axioms: \[([^\]]*)\]|does not depend on any axioms)"
for name,raw in re.findall(pattern,text,re.S):
    if name in found:raise SystemExit('Duplicate axiom report: '+name)
    axioms={a.strip() for a in raw.split(',') if a.strip()}
    if axioms-allowed:raise SystemExit('Unapproved axiom dependencies: '+repr(axioms-allowed))
    found[name]=axioms
if set(found)!=expected:raise SystemExit('Missing/unexpected declarations: '+repr(set(found)^expected))
print(f'{len(found)} declarations checked; only standard Lean logical axioms allowed.')
