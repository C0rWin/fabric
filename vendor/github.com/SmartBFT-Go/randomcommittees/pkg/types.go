// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package committee

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
)

type PublicKey []byte

type PrivateKey []byte

// Commitment represents a commitment to randomness of a node
type Commitment struct {
	Data  []byte // Data should be persisted for future initialization
	Proof []byte // Proof denotes the proof the data was honestly computed
	From  int32 // From who this commitment was sent
}

// ReconShare represents a share for reconstructing the randomness of a node
type ReconShare struct {
	Data  []byte // Data should be persisted for future initialization
	Proof []byte // Proof denotes the proof the data was honestly computed
	About int32 // About denotes whose randomness are we reconstructing
	From  int32 // Who sent this ReconShare
}

// Config is the configuration of a committee
type Config struct {
	// Nodes denotes all nodes the committee can be selected from
	Nodes Nodes
	// How many consensus rounds at minimum the committee remains
	MinimumLifespan int32
	// FailedTotalNodesPercentage is the assumed upper bound
	// on the percentage of nodes that can fail out of all nodes
	// in the network.
	FailedTotalNodesPercentage int64
	// InverseFailureChance is 1/p where p is the probability
	// to select more than a third
	// of failed nodes to the committee.
	// The higher this number is, the larger the committee.
	// The lower this number is, the bigger chance to select
	// a committee with too many failed nodes.
	InverseFailureChance int64
	// ExcludedNodes are nodes the current committee decided
	// not to be included in this committee
	ExcludedNodes []int32
	// MandatoryNodes are nodes that current committee decided
	// that must be in this committee
	MandatoryNodes []int32
	// Weights denote relative multipliers for each node's chance
	// to be selected into a committee.
	Weights []Weight
}

func (config *Config) Unmarshal(bytes []byte) error {
	_, err := asn1.Unmarshal(bytes, config)
	return err
}

func (config *Config) Marshal() []byte {
	bytes, err := asn1.Marshal(*config)
	if err != nil {
		panic(err)
	}
	return bytes
}

// Weight is a mapping between a node's identifier
// and a relative multiplier.
type Weight struct {
	ID, Weight int32
}

// Node denotes a node in our protocol,
// which is identified by an identifier and a public key
type Node struct {
	ID     int32
	PubKey []byte
}

// Nodes is an aggregation of multiple nodes
type Nodes []Node

func (nodes Nodes) String() string {
	var a []string
	for _, n := range nodes {
		a = append(a, fmt.Sprintf("%d: %s", n.ID, base64.StdEncoding.EncodeToString(n.PubKey)))
	}

	return fmt.Sprintf("%s", a)
}

// IDs returns the identifiers of all nodes
func (nodes Nodes) IDs() []int32 {
	var ids []int32
	for _, node := range nodes {
		ids = append(ids, node.ID)
	}
	return ids
}

// PubKeys returns the public keys of the Nodes in the same order they appear
func (nodes Nodes) PubKeys() [][]byte {
	var res [][]byte
	for _, n := range nodes {
		res = append(res, n.PubKey)
	}
	return res
}

// State denotes the data structures that we should persist
// and input to the committee selection at each round.
type State interface {
	Initialize([]byte) error
	ToBytes() []byte
}

// Input is what the committee selection library consumes each round
type Input struct {
	// Commitments denotes commitments arriving from nodes
	Commitments []Commitment
	// ReconShares denote the ReconShares received from all nodes if applicable
	ReconShares []ReconShare
	// NextConfig is the configuration of the next committee selection if applicable
	NextConfig Config
}

// Feedback denotes the action the committee selection library wants us to perform,
// namely to send a Commitment or ReconShares or to notify that a new committee has been selected
type Feedback struct {
	Commitment    *Commitment  // Commitment to broadcast, if applicable
	ReconShares   []ReconShare // ReconShares to broadcast, if applicable
	NextCommittee []int32     // The next committee, if applicable. It may be equal to the current committee
}
