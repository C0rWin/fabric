package mocks

type Id2IdentitiesFetcherMock struct {
}

func (*Id2IdentitiesFetcherMock) Id2Identities(cid string) map[uint64][]byte {
	return map[uint64][]byte{
		0: []byte("Alice"),
	}
}
