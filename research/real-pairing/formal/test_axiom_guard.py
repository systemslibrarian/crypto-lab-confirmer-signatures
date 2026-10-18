"""Negative controls for the proof-evidence gate itself."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
NAMES=['completeness','differenceEquations','responseDifferenceNonzero','extraction',
 'branchSpecialSoundness','orSpecialSoundness','falseStatementUniqueChallenge',
 'simulatorAccepts','maskEquiv','betaEquiv','printedBetaIsIdentity',
 'uniformEquiv','honestRandomnessEquiv','honestBranchUniform']
GOOD='\n'.join("'SignatureGate.%s' depends on axioms: [propext, Classical.choice, Quot.sound]"%n for n in NAMES)
class AxiomGuard(unittest.TestCase):
    def check(self,text):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'axioms.txt';p.write_text(text)
            return subprocess.run([sys.executable,str(Path(__file__).with_name('check_axioms.py')),str(p)],capture_output=True).returncode
    def test_complete_standard_report_passes(self):self.assertEqual(self.check(GOOD),0)
    def test_missing_or_empty_report_fails(self):
        for s in ['',GOOD.split('\n',1)[1]]:self.assertNotEqual(self.check(s),0)
    def test_incomplete_custom_and_native_axioms_fail(self):
        for ax in ['sorryAx','MyUnprovedAssumption','Lean.ofReduceBool','Lean.trustCompiler']:
            with self.subTest(axiom=ax):self.assertNotEqual(self.check(GOOD.replace('propext',ax,1)),0)
    def test_duplicate_report_fails(self):self.assertNotEqual(self.check(GOOD+'\n'+GOOD.splitlines()[0]),0)
if __name__=='__main__':unittest.main()
