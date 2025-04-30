package koinu

import (
	"fmt"
	"strings"
)

// Koinu is the smallest unit of Dogecoin.
// This type is used to represent currency in transactions.
type Koinu int64

// OneDoge is one Dogecoin represented in Koinu, the smallest unit of Dogecoin.
const OneDoge = 100_000_000 // 100 million Koinu (8 zeroes)

// MaxMoney is the maximum Koinu value that can be used in a transaction.
const MaxMoney = 10_000_000_000 * OneDoge // max transaction is 10,000,000,000 Doge

// String implements fmt.Stringer
func (val Koinu) String() string {
	whole := val / OneDoge
	part := val % OneDoge
	if part != 0 {
		// decimal number: trim off trailing zeroes in the decimal-part
		return strings.TrimRight(fmt.Sprintf("%d.%d", whole, part), "0")
	} else {
		// whole integer
		return fmt.Sprintf("%d", whole)
	}
}
