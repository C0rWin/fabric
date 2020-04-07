// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import common "github.com/hyperledger/fabric/protos/common"

import mock "github.com/stretchr/testify/mock"

// MessageCryptoVerifier is an autogenerated mock type for the MessageCryptoVerifier type
type MessageCryptoVerifier struct {
	mock.Mock
}

// VerifyHeader provides a mock function with given fields: chainID, signedBlock
func (_m *MessageCryptoVerifier) VerifyHeader(chainID string, signedBlock *common.Block) error {
	ret := _m.Called(chainID, signedBlock)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, *common.Block) error); ok {
		r0 = rf(chainID, signedBlock)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}