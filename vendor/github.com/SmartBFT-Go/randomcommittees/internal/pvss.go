/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cs

import (
	"encoding/asn1"
	"fmt"
	"sync"
	"sync/atomic"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
)

// This file implements the PVSS scheme of:
// "A Simple Publicly Verifiable Secret Sharing Scheme and its Application to Electronic Voting"
// by Berry Schoenmakers.

// The generator G in the paper is denoted here as h.

var (
	suite = suites.MustFind("Ed25519")
	g     = suite.Point().Base()
	h     = suite.Point().Pick(suite.XOF([]byte("Random Committee Selection")))
)

type PVSS struct {
	Commitments          []kyber.Point // g^{α_i} for i from 0 to f
	EncryptedEvaluations []kyber.Point // {pk_i}^{p(i)} for i from 1 to n
	Proofs               SerializedProofs
}

func (pvss *PVSS) Commit(threshold int, pubKeys []kyber.Point) error {
	*pvss = PVSS{} // Restart internal state

	secret := suite.Scalar().Pick(suite.RandomStream())

	// Secret share the secret as a polynomial
	// {α_0, α_1, ..., α_f}    p(x) = Σ α_i * x^i
	polynomialCoefficients := share.NewPriPoly(suite, threshold, secret, suite.RandomStream())

	// Commit to the polynomial coefficients
	// g^{α_i}
	_, pvss.Commitments = polynomialCoefficients.Commit(g.Clone()).Info()

	// Compute evaluations of the polynomial for each party i from 1 to n to yield { p(i) }
	polynomialEvaluationsPerPartyIndex := polynomialCoefficients.Shares(len(pubKeys))
	var polynomialEvaluationsPerParties []kyber.Scalar
	for _, e := range polynomialEvaluationsPerPartyIndex {
		polynomialEvaluationsPerParties = append(polynomialEvaluationsPerParties, e.V)
	}

	// Encrypt the evaluations of p(i) with the public keys
	for i, pk := range pubKeys {
		enc := suite.Point().Mul(polynomialEvaluationsPerPartyIndex[i].V, pk)
		pvss.EncryptedEvaluations = append(pvss.EncryptedEvaluations, enc)
	}

	// Create DLEQ ZKPs that prove that commitments on evaluations have
	// the same discrete log as the encryptions.

	var proofs []DLEQ

	for i, pk := range pubKeys {
		g1 := g.Clone()
		g2 := pk.Clone()
		h1 := commitmentOnPolynomialEvaluation(int64(i+1), pvss.Commitments)
		h2 := pvss.EncryptedEvaluations[i]

		proof := DLEQ{
			G1: g1,
			G2: g2,
			H1: h1,
			H2: h2,
		}
		proofs = append(proofs, proof)
	}

	var err error
	pvss.Proofs, err = DLEQBatch(proofs).Prove(polynomialEvaluationsPerParties)
	if err != nil {
		return fmt.Errorf("failed generating proof batch: %v", err)
	}

	return nil
}

func (pvss PVSS) VerifyCommit(pubKeys []kyber.Point) error {
	if len(pubKeys) != len(pvss.Proofs.Proofs) {
		return fmt.Errorf("have %d public keys but %d proofs to verify", len(pubKeys), len(pvss.Proofs.Proofs))
	}

	// Prepare the batch of DLEQ statements to verify
	statementsToVerify := make(DLEQBatch, 0)

	for i, pk := range pubKeys {
		// Create commitment for evaluation of the polynomial from commitments on coefficients
		h1 := commitmentOnPolynomialEvaluation(int64(i+1), pvss.Commitments)
		h2 := pvss.EncryptedEvaluations[i]

		// Verify ZKP that the exponent of the encrypted share (h2) is the same as the combined commitment above (h1)
		dleq := DLEQ{
			G1: g.Clone(),
			G2: pk.Clone(),
			H1: h1,
			H2: h2,
		}

		statementsToVerify = append(statementsToVerify, dleq)
	}

	return statementsToVerify.Verify(pvss.Proofs.Proofs)
}

// Index2Share maps an index in [1, n] to its share
type Index2Share map[int64]kyber.Point

func (i2s Index2Share) keys() []int64 {
	var res []int64
	for k := range i2s {
		res = append(res, k)
	}

	return res
}

func ReconstructShare(x2y Index2Share) kyber.Point {
	sss := SSS{
		Threshold: len(x2y),
	}

	res := suite.Point().Null()

	for x, y := range x2y {
		coefficient := sss.LagrangeCoefficient(x, x2y.keys()...)
		res.Add(res, suite.Point().Mul(coefficient, y)) // {s_i}^{lambda_i}
	}
	return res
}

func VerifyDecShare(pk, d, e kyber.Point, proof SerializedProof) error {
	// Verify that there exists an α such that:
	// 1) pk = h^α
	// 2) e  = d^α
	dleq := DLEQ{
		G1: h.Clone(),
		G2: d.Clone(),
		H1: pk.Clone(),
		H2: e.Clone(),
	}

	if err := dleq.Verify(proof); err != nil {
		return fmt.Errorf("failed verifying share decryption proof: %v", err)
	}
	return nil
}

func DecryptShare(pk kyber.Point, privateKey kyber.Scalar, e kyber.Point) (kyber.Point, SerializedProof, error) {
	// d is decrypted share, where e is encrypted share
	d := suite.Point().Mul(suite.Scalar().Inv(privateKey), e)

	// Prove that there exists an α such that:
	// 1) public key is h^α
	// 2) encrypted share is d^α
	dleq := DLEQ{
		G1: h.Clone(),
		G2: d.Clone(),
		H1: pk.Clone(),
		H2: e.Clone(),
	}

	proof, err := dleq.Prove(privateKey)
	if err != nil {
		return nil, SerializedProof{}, err
	}

	return d, proof, nil
}

type DLEQBatch []DLEQ

func (dleqs DLEQBatch) Prove(alphas []kyber.Scalar) (SerializedProofs, error) {

	if len(dleqs) != len(alphas) {
		return SerializedProofs{}, fmt.Errorf("got %d scalars but have %d proofs", len(alphas), len(dleqs))
	}

	// Create aggregated challenge over all elements
	var accumulatedPoints []kyber.Point
	for _, dleq := range dleqs {
		accumulatedPoints = append(accumulatedPoints, dleq.G1, dleq.G2, dleq.H1, dleq.H2)
	}

	var commits []struct {
		w  kyber.Scalar
		a1 kyber.Point
		a2 kyber.Point
	}
	for _, dleq := range dleqs {
		// Commit to scalar w: ( a1=g1^w, a2=g2^w )
		a1, a2, w := dleq.commit()

		// Add a1, a2 to accumulated points
		accumulatedPoints = append(accumulatedPoints, a1, a2)

		commits = append(commits, struct {
			w  kyber.Scalar
			a1 kyber.Point
			a2 kyber.Point
		}{w: w, a1: a1, a2: a2})
	}

	combinedChallenge := hashBasedRandomOracle(accumulatedPoints...)
	challengeFromVerifier := func(points ...kyber.Point) kyber.Scalar {
		return combinedChallenge
	}

	var serializedProofs SerializedProofs
	for i, dleq := range dleqs {
		dleq.computeChallenge = challengeFromVerifier
		sp, err := dleq.prove(alphas[i], commits[i].a1, commits[i].a2, commits[i].w)
		if err != nil {
			return serializedProofs, fmt.Errorf("failed producing proof: %v", err)
		}
		serializedProofs.Proofs = append(serializedProofs.Proofs, sp)
	}
	return serializedProofs, nil
}

func (dleqs DLEQBatch) Verify(proofs []SerializedProof) error {
	if len(dleqs) != len(proofs) {
		return fmt.Errorf("expected proofs for %d statements but got %d proofs", len(dleqs), len(proofs))
	}

	// Create aggregated challenge over all elements
	var accumulatedPoints []kyber.Point
	for _, dleq := range dleqs {
		accumulatedPoints = append(accumulatedPoints, dleq.G1, dleq.G2, dleq.H1, dleq.H2)
	}

	// Add a1, a2 to accumulated points across all proofs
	// as well as refined the serialized proofs into points and scalars
	var refinedProofs []struct {
		r  kyber.Scalar
		a1 kyber.Point
		a2 kyber.Point
	}

	for _, proof := range proofs {
		a1 := suite.Point()
		a2 := suite.Point()
		if err := a1.UnmarshalBinary(proof.A1); err != nil {
			return fmt.Errorf("failed unmarshaling a1: %v", err)
		}
		if err := a2.UnmarshalBinary(proof.A2); err != nil {
			return fmt.Errorf("failed unmarshaling a2: %v", err)
		}
		r := suite.Scalar()
		if err := r.UnmarshalBinary(proof.R); err != nil {
			return fmt.Errorf("failed unmarshaling r: %v", err)
		}
		accumulatedPoints = append(accumulatedPoints, a1, a2)
		refinedProofs = append(refinedProofs, struct {
			r  kyber.Scalar
			a1 kyber.Point
			a2 kyber.Point
		}{
			r:  r,
			a1: a1,
			a2: a2,
		})
	}

	combinedChallenge := hashBasedRandomOracle(accumulatedPoints...)
	challengeFromVerifier := func(points ...kyber.Point) kyber.Scalar {
		return combinedChallenge
	}

	// Start verifying proofs in parallel
	var wg sync.WaitGroup
	wg.Add(len(dleqs))

	atomicErr := &atomic.Value{}

	for i, proof := range refinedProofs {
		go func(dleq DLEQ, r kyber.Scalar, a1, a2 kyber.Point) {
			defer wg.Done()
			// Override challenge
			dleq.computeChallenge = challengeFromVerifier
			if err := dleq.verify(r, a1, a2); err != nil {
				atomicErr.Store(err)
			}
		}(dleqs[i], proof.r, proof.a1, proof.a2)
	}

	wg.Wait()

	if atomicErr.Load() == nil {
		return nil
	}

	return atomicErr.Load().(error)
}

// DLEQ is a NIZK that proves/verifies there exists
// some scalar α such that:
// (1) g1^α = h1
// (2) g2^α = h2
type DLEQ struct {
	G1, H1, G2, H2   kyber.Point
	computeChallenge func(points ...kyber.Point) kyber.Scalar
}

func (dleq DLEQ) commit() (kyber.Point, kyber.Point, kyber.Scalar) {
	w := suite.Scalar().Pick(suite.RandomStream())
	a1 := suite.Point().Mul(w, dleq.G1)
	a2 := suite.Point().Mul(w, dleq.G2)

	return a1, a2, w
}

func (dleq DLEQ) prove(alpha kyber.Scalar, a1, a2 kyber.Point, w kyber.Scalar) (SerializedProof, error) {
	c := dleq.computeChallenge(dleq.G1, dleq.G2, dleq.H1, dleq.H2, a1, a2)
	alphaTimesC := suite.Scalar().Mul(alpha, c)
	r := suite.Scalar().Sub(w, alphaTimesC)

	rBytes, err := r.MarshalBinary()
	if err != nil {
		return SerializedProof{}, fmt.Errorf("failed marshaling r: %v", err)
	}

	a1Bytes, err := a1.MarshalBinary()
	if err != nil {
		return SerializedProof{}, fmt.Errorf("failed marshaling a1: %v", err)
	}

	a2Bytes, err := a2.MarshalBinary()
	if err != nil {
		return SerializedProof{}, fmt.Errorf("failed marshaling a2: %v", err)
	}

	return SerializedProof{
		R:  rBytes,
		A1: a1Bytes,
		A2: a2Bytes,
	}, nil
}

func (dleq DLEQ) Prove(alpha kyber.Scalar) (SerializedProof, error) {
	if dleq.computeChallenge == nil {
		dleq.computeChallenge = hashBasedRandomOracle
	}
	a1, a2, w := dleq.commit()
	return dleq.prove(alpha, a1, a2, w)
}

func (dleq DLEQ) Verify(proof SerializedProof) error {
	if dleq.computeChallenge == nil {
		dleq.computeChallenge = hashBasedRandomOracle
	}
	a1 := suite.Point()
	a2 := suite.Point()
	if err := a1.UnmarshalBinary(proof.A1); err != nil {
		return fmt.Errorf("failed unmarshaling a1: %v", err)
	}
	if err := a2.UnmarshalBinary(proof.A2); err != nil {
		return fmt.Errorf("failed unmarshaling a2: %v", err)
	}

	r := suite.Scalar()
	if err := r.UnmarshalBinary(proof.R); err != nil {
		return fmt.Errorf("failed unmarshaling r: %v", err)
	}

	return dleq.verify(r, a1, a2)
}

func (dleq DLEQ) verify(r kyber.Scalar, a1, a2 kyber.Point) error {
	x1 := suite.Point().Mul(r, dleq.G1)
	x2 := suite.Point().Mul(r, dleq.G2)

	c := dleq.computeChallenge(dleq.G1, dleq.G2, dleq.H1, dleq.H2, a1, a2)

	y1 := suite.Point().Mul(c, dleq.H1)
	y2 := suite.Point().Mul(c, dleq.H2)

	b1 := suite.Point().Add(x1, y1)
	b2 := suite.Point().Add(x2, y2)

	if !a1.Equal(b1) {
		return fmt.Errorf("a1 != g1^r * h1^c")
	}

	if !a2.Equal(b2) {
		return fmt.Errorf("a2 != g2^r * h2^c")
	}

	return nil
}

func hashBasedRandomOracle(points ...kyber.Point) kyber.Scalar {
	h := suite.Hash()
	for _, p := range points {
		p.MarshalTo(h)
	}

	digest := h.Sum(nil)

	return suite.Scalar().Pick(suite.XOF(digest))
}

type SerializedProof struct {
	R  []byte
	A1 []byte
	A2 []byte
}

type SerializedProofs struct {
	Proofs []SerializedProof
}

func (sps SerializedProofs) ToBytes() ([]byte, error) {
	return asn1.Marshal(sps)
}

func (sps *SerializedProofs) Initialize(bytes []byte) error {
	_, err := asn1.Unmarshal(bytes, sps)
	return err
}

func (sp SerializedProof) ToBytes() ([]byte, error) {
	return asn1.Marshal(sp)
}

func (sp *SerializedProof) Initialize(bytes []byte) error {
	_, err := asn1.Unmarshal(bytes, sp)
	return err
}

type SSS struct {
	Threshold int
}

func (sss *SSS) LagrangeCoefficient(evaluatedAt int64, evaluationPoints ...int64) kyber.Scalar {
	// Initialize total product to be the identity element
	prod := suite.Scalar().One()

	for _, j := range evaluationPoints {
		if evaluatedAt == j {
			continue
		}

		iScalar := suite.Scalar().SetInt64(evaluatedAt)
		jScalar := suite.Scalar().SetInt64(j)

		nominator := jScalar.Clone()                        // j
		denominator := suite.Scalar().Sub(jScalar, iScalar) // j-i

		division := suite.Scalar().Div(nominator, denominator) // j / (j-i)

		prod.Mul(prod, division) // add to the product
	}

	return prod
}

func Exp(x kyber.Scalar, exponent int) kyber.Scalar {
	if exponent < 0 {
		panic("negative exponentiation shouldn't be used in this scheme")
	}

	if exponent == 0 {
		return suite.Scalar().One()
	}

	if exponent == 1 {
		return x
	}

	squaredX := suite.Scalar().Mul(x, x)

	if exponent%2 == 0 {
		return Exp(squaredX, exponent/2)
	}

	return suite.Scalar().Mul(x, Exp(squaredX, (exponent-1)/2))
}
