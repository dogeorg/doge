/*
Koinu parser: 8 significant decimal places, `int64` result.

All Dogecoin amounts are represented as `int64` on the blockchain.
Core outputs strings in 8-decimal-place format via JSON RPC in some
cases; this recovers those outputs accurately without floating-point
rounding. Also checks for overflow and values greater than MaxMoney.
*/

package koinu

import "errors"

var ErrMaxMoney = errors.New("greater than max-money (10,000,000,000 DOGE)")
var ErrInvalidNumber = errors.New("invalid number (unexpected character)")

const maxMoneyDigits = 11                  // number of integer-part digits in MaxMoney
const maxKoinuDigits = 8                   // number of fraction-part digits in OneDoge
const maxMoneyInteger = MaxMoney / OneDoge // MaxMoney integer-part, to avoid overflow

// decimalScale is 8 powers of 10, reversed for 'length' indexing.
// as a special case, length zero yields a zero.
var decimalScale = []int64{0, 10_000_000, 1_000_000, 100_000, 10_000, 1000, 100, 10, 1}

// ParseKoinu parses a decimal string like "12.6251" to Koinu (1262510000)
// Dogecoin decimals are significant to 8 places at the protocol level
// and are encoded in transactions as 64-bit integers.
func ParseKoinu(amt string) (Koinu, error) {
	chars := []uint8(amt)
	sign := int64(1)
	len := len(amt)
	i := 0

	// optional minus sign
	if i < len && chars[i] == '-' {
		sign = -1
		i++
	}

	// skip leading zeroes (because we limit to maxMoneyDigits)
	for i < len && chars[i] == '0' {
		i++
	}

	// whole number part
	whole, i := parseUInt64(chars, i, len, maxMoneyDigits)
	moreDigits := (i < len && chars[i]-'0' < 10)
	if whole > maxMoneyInteger || moreDigits {
		// whole part is greater than MaxMoney
		return 0, ErrMaxMoney
	}

	whole = whole * OneDoge // overflow: safe due to check above (approx. 1/10 of MaxInt64)

	// decimal part, up to 8 significant digits
	if i < len && chars[i] == '.' {
		start := i + 1
		part, end := parseUInt64(chars, start, len, maxKoinuDigits)
		i = end

		// decimal part must be 8 digits; multiply by 10 ^ (8 - length)
		// e.g. if we found 6 digits, multiply by 100
		length := end - start
		part *= decimalScale[length]

		whole += part // overflow: safe, less than OneDoge

		// decmial part can push us above MaxMoney
		if whole > MaxMoney {
			return 0, ErrMaxMoney
		}
	}

	// invalid if string contains more charcters (but skip extra decimal-part digits)
	i = skipDigits(chars, i, len)
	if i != len {
		return 0, ErrInvalidNumber
	}

	return Koinu(sign * whole), nil
}

// parseUInt64 is like strconv.Atoi with int64 result and a maximum length.
func parseUInt64(chars []uint8, i int, len int, maxlen int) (int64, int) {
	end := i + maxlen
	if end > len {
		end = len // min()
	}
	val := int64(0)
	for i < end {
		// the following test relies on unsigned modulo math
		ch := chars[i] - '0'
		if ch < 10 {
			val = val*10 + int64(ch)
			i++
		} else {
			break // not a digit
		}
	}
	return val, i
}

func skipDigits(chars []uint8, i int, len int) int {
	for i < len && chars[i]-'0' < 10 {
		i++
	}
	return i
}
