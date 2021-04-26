// Code generated by mockery v2.7.4. DO NOT EDIT.

package mocks

import (
	io "io"

	committee "github.com/SmartBFT-Go/randomcommittees/pkg"

	mock "github.com/stretchr/testify/mock"
)

// CommitteeSelection is an autogenerated mock type for the CommitteeSelection type
type CommitteeSelection struct {
	mock.Mock
}

// GenerateKeyPair provides a mock function with given fields: rand
func (_m *CommitteeSelection) GenerateKeyPair(rand io.Reader) (committee.PublicKey, committee.PrivateKey, error) {
	ret := _m.Called(rand)

	var r0 committee.PublicKey
	if rf, ok := ret.Get(0).(func(io.Reader) committee.PublicKey); ok {
		r0 = rf(rand)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(committee.PublicKey)
		}
	}

	var r1 committee.PrivateKey
	if rf, ok := ret.Get(1).(func(io.Reader) committee.PrivateKey); ok {
		r1 = rf(rand)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(committee.PrivateKey)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(io.Reader) error); ok {
		r2 = rf(rand)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// Initialize provides a mock function with given fields: ID, PrivateKey, nodes
func (_m *CommitteeSelection) Initialize(ID int32, PrivateKey committee.PrivateKey, nodes committee.Nodes) error {
	ret := _m.Called(ID, PrivateKey, nodes)

	var r0 error
	if rf, ok := ret.Get(0).(func(int32, committee.PrivateKey, committee.Nodes) error); ok {
		r0 = rf(ID, PrivateKey, nodes)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Process provides a mock function with given fields: _a0, _a1
func (_m *CommitteeSelection) Process(_a0 committee.State, _a1 committee.Input) (committee.Feedback, committee.State, error) {
	ret := _m.Called(_a0, _a1)

	var r0 committee.Feedback
	if rf, ok := ret.Get(0).(func(committee.State, committee.Input) committee.Feedback); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Get(0).(committee.Feedback)
	}

	var r1 committee.State
	if rf, ok := ret.Get(1).(func(committee.State, committee.Input) committee.State); ok {
		r1 = rf(_a0, _a1)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(committee.State)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(committee.State, committee.Input) error); ok {
		r2 = rf(_a0, _a1)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// VerifyCommitment provides a mock function with given fields: _a0
func (_m *CommitteeSelection) VerifyCommitment(_a0 committee.Commitment) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(committee.Commitment) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VerifyReconShare provides a mock function with given fields: _a0
func (_m *CommitteeSelection) VerifyReconShare(_a0 committee.ReconShare) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(committee.ReconShare) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
