// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package committee

import "io"

// Selection is an interface that describes the API of the committee selection library
type Selection interface {
	// GeneratePrivateKey generates a private key for an instance using the given randomness
	GenerateKeyPair(rand io.Reader) (PublicKey, PrivateKey, error)
	// Initialize initializes the committee selection instance with the given identifier and private key,
	// as well as with all the other nodes.
	Initialize(ID int32, PrivateKey []byte, nodes Nodes) error
	// Process interacts with the committee selection and feeds it with events of other remote instances from Input,
	// and receives feedback on a committee change or requests of messages to be sent via Feedback.
	// The operation operates on the given state and the new state is returned.
	Process(State, Input) (Feedback, State, error)
	// VerifyCommitment should be called whenever the node receives a commitment
	// and before passing it to the library or persisting it
	VerifyCommitment(Commitment) error
	// VerifyReconShare should be called whenever the node receives a ReconShare
	// and before passing it to the library or persisting it
	VerifyReconShare(ReconShare) error
}


// Logger defines the contract for logging.
type Logger interface {
	Debugf(template string, args ...interface{})
	Infof(template string, args ...interface{})
	Errorf(template string, args ...interface{})
	Warnf(template string, args ...interface{})
	Panicf(template string, args ...interface{})
}