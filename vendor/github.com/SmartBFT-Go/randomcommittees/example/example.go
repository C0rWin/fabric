// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package example

import (
	"crypto/rand"
	"testing"

	"github.com/SmartBFT-Go/randomcommittees/example/mock"
	pvss "github.com/SmartBFT-Go/randomcommittees/pkg"
)

type comm struct {
}

func (c comm) Send(_ interface{}) {

}

func (c comm) Receive() (pvss.Commitment, []pvss.ReconShare) {
	return pvss.Commitment{}, nil
}

func toBytes(_ interface{}) []byte {
	return nil
}

var (
	reconsShare1 = pvss.ReconShare{}
	reconsShare2 = pvss.ReconShare{}
	publicKey1   []byte
	publicKey2   []byte
)

func TestAPIUsage(t *testing.T) {
	cs := &mock.CommitteeSelectionMock{}

	// Generate our public, private key that will be used for other parties
	// to encrypt data sent to us
	pubKey, privKey, err := cs.GeneratePrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating private key: %v", err)
	}

	// Save private key to stable storage
	// ...

	// Publish our public key to everyone
	_ = pubKey
	// ...

	cs.Initialize(13, privKey)

	// We are ready to start the protocol.
	// In the first round we didn't receive anything from anyone,
	// and the state is empty.
	// If we start the protocol from a round that is not the first round,
	// then we must load the state from stable storage.
	// The received commitments and ReconShares can be nil and it's fine

	var state pvss.State
	var receivedCommitments []pvss.Commitment
	var receivedReconShares []pvss.ReconShare

	var comm comm

	for {
		output, newState := cs.Process(state, pvss.Input{
			Commitments: receivedCommitments,
			ReconShares: receivedReconShares,
		})

		state = newState

		if output.Commitment != nil {
			comm.Send(output.Commitment)
		}
		for _, rcs := range output.ReconShares {
			comm.Send(rcs)
		}

		for _, id := range output.NextCommittee {
			if id == 13 {
				// We are in the committee
			} else {
				// We are not in the committee
			}
		}

		receivedCommitments = nil
		receivedReconShares = nil
		// Receive commitments from other nodes
		unverifiedCommitment, unverifiedReconshares := comm.Receive()
		err := cs.VerifyCommitment(unverifiedCommitment, publicKey1)
		if err != nil {
			// Ignore this commitment as it is maliciously crafted
		} else {
			receivedCommitments = []pvss.Commitment{unverifiedCommitment}
		}
		for _, unverifiedReconshare := range unverifiedReconshares {
			err = cs.VerifyReconShare(reconsShare1, publicKey1)
			if err != nil {
				// Ignore this ReconShare as it is maliciously crafted
				continue
			}
			receivedReconShares = append(
				receivedReconShares,
				unverifiedReconshare)
		}
	} // for

}
