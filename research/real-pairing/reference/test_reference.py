"""Cross-library acceptance and rejection tests; not an external security audit."""
import copy
import json
import unittest
from pathlib import Path
from verify import verify, pair, point, target, Q, P

FIXTURE=json.loads(Path(__file__).with_name('vectors.json').read_text())
VECTORS={v['name']:v['transcript'] for v in FIXTURE['vectors']}

def changed(name, path, value):
    d=copy.deepcopy(VECTORS[name]); at=d
    for k in path[:-1]:at=at[k]
    at[path[-1]]=value
    return d

class ReferenceVerifier(unittest.TestCase):
    def test_pairing_convention_has_three_fixed_anchors(self):
        self.assertEqual(len(FIXTURE['pairingAnchors']),3)
        for a in FIXTURE['pairingAnchors']:
            with self.subTest(anchor=a['name']):
                self.assertEqual(pair(point(a['g1'],1),point(a['g2'],2)),target(a['target']))

    def test_both_roles_both_relations_and_two_simulations(self):
        self.assertEqual(len(VECTORS),6)
        for name,t in VECTORS.items():
            with self.subTest(name=name):self.assertTrue(verify(t))
        # These are deliberately false relations with equations that pass.
        # This acceptance is required: file verification does not certify timing.
        self.assertIn('leaves',VECTORS['simulated-confirmation']['publicData']['message'])
        self.assertIn('stays',VECTORS['simulated-disavowal']['publicData']['message'])

    def test_all_response_coordinates_are_bound(self):
        for name in ['confirmer-confirmation','confirmer-disavowal','signer-disavowal']:
            for key,value in VECTORS[name]['proof']['response'].items():
                with self.subTest(name=name,field=key):
                    d=changed(name,['proof','response',key],format((int(value,16)+1)%Q,'x'))
                    self.assertFalse(verify(d))

    def test_recording_rejects_a_different_challenge(self):
        for name,t in VECTORS.items():
            c=format((int(t['proof']['challenge'],16)+1)%Q,'x')
            self.assertFalse(verify(changed(name,['proof','challenge'],c)),name)

    def test_noncanonical_and_out_of_field_scalars_reject(self):
        for value in ['00','01','-1','0x17','AB',format(Q,'x'),17,None]:
            with self.subTest(value=value):
                self.assertFalse(verify(changed('confirmer-confirmation',['proof','challenge'],value)))

    def test_message_format_and_key_certificate_are_checked(self):
        for path,value in [(['publicData','message'],'Another message'),
                           (['publicData','scheme'],'unknown'),
                           (['publicData','confirmerKeyProof','z'],'0'),
                           (['publicData','signature','s'],'0'),
                           (['publicData','signature','t'],'0'),
                           (['publicData','signerPublic'],'c0'+'00'*95)]:
            self.assertFalse(verify(changed('confirmer-confirmation',path,value)),path)
        self.assertFalse(verify(changed('confirmer-disavowal',['publicData','message'],
            VECTORS['confirmer-confirmation']['publicData']['message'])))

    def test_subgroup_identity_and_noncanonical_target_values_reject(self):
        for values in [['0']*12,['1']+['0']*11,[format(P-1,'x')]+['0']*11,
                       [format(P,'x')]+['0']*11,['00']+['0']*11,['1']]:
            with self.subTest(values=values[:1]):
                self.assertFalse(verify(changed('confirmer-disavowal',['proof','firstMessage','beta1'],values)))
        self.assertFalse(verify(changed('confirmer-confirmation',['proof','firstMessage','z2'],'invalid')))

    def test_verdict_metadata_has_no_authority(self):
        d=copy.deepcopy(VECTORS['confirmer-confirmation']);d['verified']=True;d['proof']['challenge']='0'
        self.assertFalse(verify(d))
        d=copy.deepcopy(VECTORS['confirmer-confirmation']);d['verified']=False;d['provenance']='untrusted text'
        self.assertTrue(verify(d))

if __name__=='__main__':unittest.main()
