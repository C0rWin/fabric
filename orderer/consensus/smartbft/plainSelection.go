/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package smartbft

import (
	"io"

	rc "github.com/SmartBFT-Go/randomcommittees/pkg"
)

type plainSelection struct {
	committee []uint32
}

func (ps *plainSelection) GenerateKeyPair(rand io.Reader) (rc.PublicKey, rc.PrivateKey, error) {
	return []byte{}, []byte{}, nil
}

func (ps *plainSelection) Initialize(ID uint32, PrivateKey []byte, nodes rc.Nodes) error {
	for _, id := range nodes.IDs() {
		ps.committee = append(ps.committee, uint32(id))
	}
	return nil
}

func (ps *plainSelection) Process(state rc.State, input rc.Input) (rc.Feedback, rc.State, error) {
	return rc.Feedback{
		NextCommittee: ps.committee,
	}, nil, nil
}

func (ps *plainSelection) VerifyCommitment(rc.Commitment, rc.PublicKey) error {
	return nil
}

func (ps *plainSelection) VerifyReconShare(rc.ReconShare, rc.PublicKey) error {
	return nil
}
