"""Cross-library acceptance and rejection tests; not an external security audit."""
import copy
import json
import unittest
from pathlib import Path
from verify import verify, verify_designated, verify_public_transferable, pair, point, target, Q, P

FIXTURE=json.loads(Path(__file__).with_name('vectors.json').read_text())
VECTORS={v['name']:v['transcript'] for v in FIXTURE['vectors']}
DV={v['name']:v for v in FIXTURE['designatedVerifier']}

def dv_changed(name, path, value):
    d=copy.deepcopy(DV[name]); at=d
    for k in path[:-1]:at=at[k]
    at[path[-1]]=value
    return d

def dv_check(vector):
    return verify_designated(vector) if vector['kind']=='designated' else verify_public_transferable(vector)

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

class DesignatedVerifierProofs(unittest.TestCase):
    """A-D-09 cross-library checks. py_ecc recomputes what Noble produced."""

    def test_both_origins_and_the_public_contrast_are_accepted(self):
        self.assertEqual(len(DV),7)
        for name,vector in DV.items():
            with self.subTest(name=name):
                self.assertTrue(dv_check(vector),name)
        # Both allowed origins exist for each role, and they are different proofs.
        for role in ('confirmer','signer'):
            a=DV[role+'-designated-from-witness']['proof']
            b=DV[role+'-designated-from-verifier-secret']['proof']
            self.assertNotEqual(a['d'],b['d'])
            self.assertEqual(sorted(a),sorted(b))

    def test_a_simulated_proof_of_a_false_statement_still_satisfies_the_equations(self):
        # This acceptance is REQUIRED. It is why a third party learns nothing:
        # the designated verifier can produce this for any statement at all.
        false_vector=DV['designated-simulated-false-statement']
        self.assertTrue(verify_designated(false_vector))
        self.assertIn('FALSE statement',false_vector['note'])
        self.assertNotEqual(false_vector['publicData']['message'],
                            DV['confirmer-designated-from-witness']['publicData']['message'])

    def test_every_designated_proof_coordinate_is_bound(self):
        for name in ('confirmer-designated-from-witness','signer-designated-from-verifier-secret'):
            vector=DV[name]
            for key,value in vector['proof'].items():
                with self.subTest(name=name,field=key):
                    if key=='tTgt':
                        broken=list(value);broken[0]=format((int(broken[0],16)+1)%P,'x')
                    else:
                        broken=format((int(value,16)+1)%Q,'x') if key in ('w','r','d') else value[:-2]+'00'
                    self.assertFalse(dv_check(dv_changed(name,['proof',key],broken)))

    def test_the_verifier_key_registration_is_required(self):
        name='confirmer-designated-from-witness'
        key=DV[name]['verifierKey']
        self.assertFalse(verify_designated(dv_changed(name,['verifierKey','response'],
            format((int(key['response'],16)+1)%Q,'x'))))
        self.assertFalse(verify_designated(dv_changed(name,['verifierKey','commitment'],
            DV[name]['verifierKey']['y'])))
        self.assertFalse(verify_designated(dv_changed(name,['verifierKey','y'],'c0'+'00'*47)))

    def test_context_role_and_statement_are_all_bound(self):
        name='confirmer-designated-from-witness'
        self.assertFalse(verify_designated(dv_changed(name,['context'],'a different context')))
        self.assertFalse(verify_designated(dv_changed(name,['role'],'signer')))
        self.assertFalse(verify_designated(dv_changed(name,['publicData','message'],'Another claim')))
        for bad in ('','x'*201,'has\x00control',7,None):
            self.assertFalse(verify_designated(dv_changed(name,['context'],bad)))
        # A proof made for the true statement does not carry over to the false one.
        swapped=copy.deepcopy(DV[name])
        swapped['publicData']=copy.deepcopy(DV['designated-simulated-false-statement']['publicData'])
        self.assertFalse(verify_designated(swapped))

    def test_the_designated_and_public_verifiers_do_not_accept_each_other(self):
        designated=DV['confirmer-designated-from-witness']
        public=DV['confirmer-public-transferable']
        self.assertFalse(verify_public_transferable(designated))
        stripped=copy.deepcopy(designated)
        stripped['proof']={k:v for k,v in stripped['proof'].items() if k not in ('w','r')}
        self.assertFalse(verify_public_transferable(stripped))
        self.assertFalse(verify_designated(public))
        padded=copy.deepcopy(public);padded['verifierKey']=designated['verifierKey']
        padded['proof']=dict(padded['proof'],w='0',r='0')
        self.assertFalse(verify_designated(padded))

    def test_public_transferable_proofs_are_bound_to_their_statement(self):
        for name in ('confirmer-public-transferable','signer-public-transferable'):
            self.assertFalse(verify_public_transferable(dv_changed(name,['proof','d'],
                format((int(DV[name]['proof']['d'],16)+1)%Q,'x'))))
            self.assertFalse(verify_public_transferable(dv_changed(name,['context'],'other')))
            self.assertFalse(verify_public_transferable(dv_changed(name,['publicData','message'],'Another claim')))

if __name__=='__main__':unittest.main()
