// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package cs

import (
	cs "github.com/SmartBFT-Go/randomcommittees/internal"
	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
)

func NewCommitteeSelection(logger committee.Logger) *cs.CommitteeSelection {
	return &cs.CommitteeSelection{
		SelectCommittee: cs.SelectCommittee,
		Logger:          logger,
	}
}
