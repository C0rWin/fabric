/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cs

import (
	"fmt"
	"math/big"
)

func CommitteeSize(totalNodeCount int64, failedTotalNodesPercentage int64, failureChance big.Rat) int {
	if totalNodeCount < 4 {
		return int(totalNodeCount)
	}

	if failedTotalNodesPercentage == 33 {
		return int(totalNodeCount)
	}

	failureChanceFloat, _ := failureChance.Float64()

	byzantineRatio := float64(failedTotalNodesPercentage) / 100

	return int(binarySearch(4, totalNodeCount, func(committeeSize int64) cmp {
		p := 1 - hyperGeomRangeSum(totalNodeCount, committeeSize, byzantineRatio)
		return failureChanceFloat > p
	}))
}

func hyperGeomRangeSum(N, n int64, byzantine float64) float64 {
	third := (n - 1) / 3
	sum := big.NewRat(0, 1)
	for t := int64(0); t <= third; t++ {
		hg := hyperGeom(N, n, t, byzantine)
		sum.Add(sum, hg)
	}

	floatSum, exact := sum.Float64()
	if !exact && floatSum > 1 {
		panic(fmt.Errorf("float sum is %f", floatSum))
	}
	return floatSum
}

func hyperGeom(total, committeeTotal, committeeByzantine int64, byzantineRatio float64) *big.Rat {
	byzantineTotal := int64(float64(total) * byzantineRatio)
	a := choose(byzantineTotal, committeeByzantine)
	b := choose(total-byzantineTotal, committeeTotal-committeeByzantine)
	c := choose(total, committeeTotal)

	ar := bigToRat(a)
	br := bigToRat(b)
	cr := bigToRat(c)

	abr := big.NewRat(1, 2).Mul(ar, br)   // a*b
	crInverse := big.NewRat(1, 2).Inv(cr) // 1/c

	return big.NewRat(1, 2).Mul(abr, crInverse) // (a*b)/c
}

func bigToRat(n *big.Int) *big.Rat {
	r, ok := big.NewRat(1, 2).SetString(n.String())
	if !ok {
		panic("failed")
	}
	return r
}

func choose(n, k int64) *big.Int {
	return big.NewInt(0).Binomial(n, k)
}

type cmp bool

const (
	bigger cmp = true
	smaller
)

func binarySearch(low, high int64, pred func(n int64) cmp) int64 {
	for low < high {
		mid := (high + low) / 2
		if pred(mid) {
			high = mid
		} else {
			low = mid + 1
		}
	}

	return low
}
