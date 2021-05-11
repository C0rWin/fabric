/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"encoding/asn1"
	"encoding/base64"

	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
	"github.com/hyperledger/fabric/protos/common"
	utils2 "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
)

// CommitteeMetadata encodes committee metadata
// for a block.
type CommitteeMetadata struct {
	State            RawState        // State of this current committee.
	Committers       []int32         // The identifiers of who committed in this committee
	FinalStateIndex  int64           // The block number of the last finalized state that was used to pick this committee
	CommitteeShiftAt int64           // The block number that contains reconstruction shares that reveal this committee
	CommitteeAtShift committee.Nodes // The committee at the time of the shift to this committee
	GenesisConfigAt  int64           // The block number of the first ever committee instance
	CommitteeSize    int32
}

func CommitteeMetadataFromBlock(block *common.Block) (*CommitteeMetadata, error) {
	if block.Header.Number == 0 {
		return nil, nil
	}

	md := utils2.GetOrdererblockMetadataOrPanic(block).CommitteeMetadata
	if len(md) == 0 {
		return nil, nil
	}
	cm := &CommitteeMetadata{}
	return cm, errors.Wrap(cm.Unmarshal(md), "failed extracting committee metadata")
}

type RawState []byte

func (rs RawState) String() string {
	return base64.StdEncoding.EncodeToString(rs)
}

func (cm *CommitteeMetadata) committed(id int32) bool {
	for _, e := range cm.Committers {
		if e == id {
			return true
		}
	}
	return false
}

func (cm *CommitteeMetadata) ShouldCommit(id int32, expectedCommitters int, logger committee.Logger) bool {
	if cm == nil {
		logger.Debugf("committee metadata is nil")
		return true
	}
	if len(cm.Committers) >= expectedCommitters {
		logger.Debugf("We have %d committers and %d are sufficient", len(cm.Committers), expectedCommitters)
		return false
	}
	logger.Debugf("We have %d committers and we need %d in total", len(cm.Committers), expectedCommitters)
	didNotCommit := !cm.committed(id)
	if didNotCommit {
		logger.Debugf("%d has not committed yet", id)
		return true
	}
	logger.Debugf("%d has already committed", id)
	return false
}

func (cm *CommitteeMetadata) Unmarshal(bytes []byte) error {
	if len(bytes) == 0 {
		return nil
	}
	_, err := asn1.Unmarshal(bytes, cm)
	return err
}

func (cm *CommitteeMetadata) Marshal() []byte {
	if cm == nil ||
		(len(cm.Committers) == 0 && len(cm.State) == 0 && cm.GenesisConfigAt == 0 && cm.FinalStateIndex == 0 && cm.CommitteeShiftAt == 0) {
		return nil
	}
	bytes, err := asn1.Marshal(*cm)
	if err != nil {
		panic(err)
	}
	return bytes
}
