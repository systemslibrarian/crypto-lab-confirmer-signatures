import Mathlib.Tactic.FieldSimp
import Mathlib.Tactic.LinearCombination
import Mathlib.Tactic.Ring
import Mathlib.Algebra.Field.Basic
import Mathlib.Probability.Distributions.Uniform
import Mathlib.Probability.ProbabilityMassFunction.Constructions

/-!
Candidate inequality OR protocol in exponent coordinates over an arbitrary field.
These are mathematical coordinates, NOT exposed discrete logarithms in the browser.
No cryptographic game, curve implementation or protocol compiler is formalized here.
-/
set_option autoImplicit false
namespace SignatureGate
variable {F : Type*} [Field F]

structure Statement (F : Type*) where
  d : F
  key : F
  b : F
  alleged : F

structure Commitment (F : Type*) where
  beta : F
  keyMask : F
  pairMask : F

structure Response (F : Type*) where
  u : F
  v : F
  challenge : F

def Witness (s : Statement F) : Prop :=
  ∃ x : F, s.key = s.d * x ∧ s.alleged ≠ s.b * x

def Accept (s : Statement F) (t : Commitment F) (r : Response F) : Prop :=
  t.beta ≠ 0 ∧ t.keyMask = s.d * r.u - s.key * r.v ∧
  t.pairMask = t.beta * r.challenge + s.b * r.u - s.alleged * r.v

/-- Completeness for every challenge, not merely sampled values. -/
theorem completeness (s : Statement F) (x a e f c : F)
    (hkey : s.key = s.d * x) (hneq : s.alleged ≠ s.b * x) (ha : a ≠ 0) :
    Accept s ⟨a * (s.b*x-s.alleged), s.d*e-s.key*f, s.b*e-s.alleged*f⟩
      ⟨e-c*x*a, f-c*a, c⟩ := by
  have hr : s.b*x-s.alleged ≠ 0 := sub_ne_zero.mpr (Ne.symm hneq)
  refine ⟨mul_ne_zero ha hr, ?_, ?_⟩
  · dsimp
    rw [hkey]
    ring
  · dsimp
    ring

/-- Two accepting responses to the same commitment give two difference equations. -/
theorem differenceEquations (s : Statement F) (t : Commitment F) (r r' : Response F)
    (h : Accept s t r) (h' : Accept s t r') :
    s.d*(r.u-r'.u)-s.key*(r.v-r'.v)=0 ∧
    t.beta*(r.challenge-r'.challenge)+s.b*(r.u-r'.u)-s.alleged*(r.v-r'.v)=0 := by
  constructor
  · linear_combination h'.2.1 - h.2.1
  · linear_combination h'.2.2 - h.2.2

/-- The denominator is proved nonzero from validation and acceptance. -/
theorem responseDifferenceNonzero (s : Statement F) (t : Commitment F) (r r' : Response F)
    (hd : s.d ≠ 0) (hc : r.challenge ≠ r'.challenge)
    (h : Accept s t r) (h' : Accept s t r') : r.v-r'.v ≠ 0 := by
  obtain ⟨hk,hp⟩ := differenceEquations s t r r' h h'
  intro hv
  have hu : r.u-r'.u=0 := by
    have hz : s.d*(r.u-r'.u)=0 := by simpa [hv] using hk
    exact (mul_eq_zero.mp hz).resolve_left hd
  have hz : t.beta*(r.challenge-r'.challenge)=0 := by simpa [hu,hv] using hp
  exact (mul_ne_zero h.1 (sub_ne_zero.mpr hc)) hz

/-- Explicit extractor, including its nonzero blinding and beta relation. -/
theorem extraction (s : Statement F) (t : Commitment F) (r r' : Response F)
    (hd : s.d ≠ 0) (hc : r.challenge ≠ r'.challenge)
    (h : Accept s t r) (h' : Accept s t r') :
    let x := (r.u-r'.u)/(r.v-r'.v)
    let a := -(r.v-r'.v)/(r.challenge-r'.challenge)
    s.key=s.d*x ∧ t.beta=a*(s.b*x-s.alleged) ∧ a≠0 ∧ s.alleged≠s.b*x := by
  dsimp
  have hv := responseDifferenceNonzero s t r r' hd hc h h'
  have hdc : r.challenge-r'.challenge ≠ 0 := sub_ne_zero.mpr hc
  obtain ⟨hk,hp⟩ := differenceEquations s t r r' h h'
  have hkey : s.key=s.d*((r.u-r'.u)/(r.v-r'.v)) := by
    field_simp [hv]
    linear_combination -hk
  have hb : t.beta=(-(r.v-r'.v)/(r.challenge-r'.challenge)) *
      (s.b*((r.u-r'.u)/(r.v-r'.v))-s.alleged) := by
    field_simp [hv,hdc]
    linear_combination (r.v-r'.v)*hp
  have ha : -(r.v-r'.v)/(r.challenge-r'.challenge) ≠ 0 :=
    div_ne_zero (neg_ne_zero.mpr hv) hdc
  refine ⟨hkey,hb,ha,?_⟩
  intro heq
  apply h.1
  rw [heq,sub_self,mul_zero] at hb
  exact hb

/-- One branch's two-special-soundness conclusion. -/
theorem branchSpecialSoundness (s : Statement F) (t : Commitment F) (r r' : Response F)
    (hd : s.d ≠ 0) (hc : r.challenge ≠ r'.challenge)
    (h : Accept s t r) (h' : Accept s t r') : Witness s := by
  have hx := extraction s t r r' hd hc h h'
  exact ⟨(r.u-r'.u)/(r.v-r'.v),hx.1,hx.2.2.2⟩

def AcceptOR (s₁ s₂ : Statement F) (t₁ t₂ : Commitment F)
    (c : F) (r₁ r₂ : Response F) : Prop :=
  r₁.challenge+r₂.challenge=c ∧ Accept s₁ t₁ r₁ ∧ Accept s₂ t₂ r₂

/-- Different overall challenges force an extractable branch in the OR proof. -/
theorem orSpecialSoundness (s₁ s₂ : Statement F) (t₁ t₂ : Commitment F)
    (c c' : F) (r₁ r₂ r₁' r₂' : Response F)
    (hd₁ : s₁.d≠0) (hd₂ : s₂.d≠0) (hc : c≠c')
    (h : AcceptOR s₁ s₂ t₁ t₂ c r₁ r₂)
    (h' : AcceptOR s₁ s₂ t₁ t₂ c' r₁' r₂') : Witness s₁ ∨ Witness s₂ := by
  by_cases hb : r₁.challenge=r₁'.challenge
  · right
    have hb₂ : r₂.challenge≠r₂'.challenge := by
      intro heq
      apply hc
      calc c = r₁.challenge+r₂.challenge := h.1.symm
           _ = r₁'.challenge+r₂'.challenge := by rw [hb,heq]
           _ = c' := h'.1
    exact branchSpecialSoundness s₂ t₂ r₂ r₂' hd₂ hb₂ h.2.2 h'.2.2
  · exact Or.inl (branchSpecialSoundness s₁ t₁ r₁ r₁' hd₁ hb h.2.1 h'.2.1)

/-- A false OR statement has at most one accepting overall challenge per commitment. -/
theorem falseStatementUniqueChallenge (s₁ s₂ : Statement F) (t₁ t₂ : Commitment F)
    (c c' : F) (r₁ r₂ r₁' r₂' : Response F)
    (hd₁ : s₁.d≠0) (hd₂ : s₂.d≠0) (hn₁ : ¬Witness s₁) (hn₂ : ¬Witness s₂)
    (h : AcceptOR s₁ s₂ t₁ t₂ c r₁ r₂)
    (h' : AcceptOR s₁ s₂ t₁ t₂ c' r₁' r₂') : c=c' := by
  by_contra hc
  exact (orSpecialSoundness s₁ s₂ t₁ t₂ c c' r₁ r₂ r₁' r₂' hd₁ hd₂ hc h h').elim hn₁ hn₂

/-- A known-challenge simulator needs no witness, even on false statements. -/
theorem simulatorAccepts (s : Statement F) (beta u v c : F) (hb : beta≠0) :
    Accept s ⟨beta,s.d*u-s.key*v,beta*c+s.b*u-s.alleged*v⟩ ⟨u,v,c⟩ :=
  ⟨hb,rfl,rfl⟩

/-- The honest-response translation is a bijection for every fixed challenge. -/
def maskEquiv (x a c : F) : (F × F) ≃ (F × F) where
  toFun p := (p.1-c*x*a,p.2-c*a)
  invFun p := (p.1+c*x*a,p.2+c*a)
  left_inv p := by ext <;> dsimp <;> ring
  right_inv p := by ext <;> dsimp <;> ring

/-- Nonidentity beta sampling is also a bijection when the ratio is nonidentity. -/
def betaEquiv (ratio : F) (hr : ratio≠0) : {a : F // a≠0} ≃ {beta : F // beta≠0} where
  toFun a := ⟨a.val*ratio,mul_ne_zero a.property hr⟩
  invFun beta := ⟨beta.val/ratio,div_ne_zero beta.property hr⟩
  left_inv a := by apply Subtype.ext; dsimp; field_simp [hr]
  right_inv beta := by apply Subtype.ext; dsimp; field_simp [hr]

/-- A permutation preserves the uniform finite probability distribution. -/
theorem uniformEquiv {α : Type*} [Fintype α] [Nonempty α] (e : α ≃ α) :
    (PMF.uniformOfFintype α).map e = PMF.uniformOfFintype α := by
  classical
  ext y
  rw [PMF.map_apply]
  rw [← e.symm.tsum_eq (fun a => if y = e a then PMF.uniformOfFintype α a else 0)]
  simp only [Equiv.apply_symm_apply, PMF.uniformOfFintype_apply]
  rw [tsum_eq_single y]
  · simp
  · intro a ha
    simp [Ne.symm ha]

/-- Joint bijection, including the dependence of the response translation on a. -/
def honestRandomnessEquiv (x ratio c : F) (hr : ratio≠0) :
    ({a : F // a≠0} × (F × F)) ≃ ({beta : F // beta≠0} × (F × F)) where
  toFun p := (betaEquiv ratio hr p.1, maskEquiv x p.1.val c p.2)
  invFun p := ((betaEquiv ratio hr).symm p.1,
    (maskEquiv x ((betaEquiv ratio hr).symm p.1).val c).symm p.2)
  left_inv p := by simp
  right_inv p := by simp

instance nonzeroNonempty : Nonempty {a : F // a≠0} := ⟨⟨1, one_ne_zero⟩⟩

/-- Exact joint distribution of (beta,u,v), for each fixed witness and challenge. -/
theorem honestBranchUniform [Fintype F] [DecidableEq F]
    (x ratio c : F) (hr : ratio≠0) :
    (PMF.uniformOfFintype ({a : F // a≠0} × (F × F))).map
      (honestRandomnessEquiv x ratio c hr) =
    PMF.uniformOfFintype ({beta : F // beta≠0} × (F × F)) := by
  exact uniformEquiv (honestRandomnessEquiv x ratio c hr)

/-- The printed key-ratio beta is identity under the stated key relation. -/
theorem printedBetaIsIdentity (d x a : F) : a*(d*x-d*x)=0 := by ring

end SignatureGate
