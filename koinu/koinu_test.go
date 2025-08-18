package koinu

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestKoinuString(t *testing.T) {
	val := Koinu(12*OneDoge + (OneDoge / 4)) // 12.25
	txt := fmt.Sprintf("%v", val)
	if txt != "12.25" {
		t.Errorf("incorrect koinu formatting: %v (expecting 12.25)", txt)
	}
}

type TestBalance struct {
	Balance Koinu `json:"balance"`
}

func TestJsonUnmarshal(t *testing.T) {
	var balance TestBalance
	err := json.Unmarshal([]byte(`{"balance": "1000"}`), &balance)
	if err != nil {
		t.Errorf("error unmarshaling JSON: %v", err)
	}

	testParse(t, balance.Balance.String(), 100000000000)
}

func TestParseKoinu(t *testing.T) {
	// simple cases
	testParse(t, "0", 0)
	testParse(t, "1", 100000000)
	testParse(t, "1.", 100000000)
	testParse(t, "1.0", 100000000)
	testParse(t, "1000", 100000000000)

	// whole numbers
	testParse(t, "1", 100000000)
	testParse(t, "25", 2500000000)
	testParse(t, "625", 62500000000)
	testParse(t, "6258", 625800000000)
	testParse(t, "62581", 6258100000000)
	testParse(t, "625819", 62581900000000)
	testParse(t, "6258192", 625819200000000)
	testParse(t, "62518192", 6251819200000000)

	// leading zeroes
	testParse(t, "000000001", 100000000)
	testParse(t, "000000025", 2500000000)
	testParse(t, "000000625", 62500000000)
	testParse(t, "000006258", 625800000000)
	testParse(t, "000062581", 6258100000000)
	testParse(t, "000625819", 62581900000000)
	testParse(t, "006258192", 625819200000000)
	testParse(t, "062518192", 6251819200000000)

	// each decimal length up to 8 places (the maximum)
	testParse(t, "12", 1200000000)
	testParse(t, "12.1", 1210000000)
	testParse(t, "12.25", 1225000000)
	testParse(t, "12.625", 1262500000)
	testParse(t, "12.6258", 1262580000)
	testParse(t, "12.62581", 1262581000)
	testParse(t, "12.625819", 1262581900)
	testParse(t, "12.6258192", 1262581920)
	testParse(t, "12.62518192", 1262518192)

	// decimal part only
	testParse(t, ".1", 10000000)
	testParse(t, ".25", 25000000)
	testParse(t, ".625", 62500000)
	testParse(t, ".6258", 62580000)
	testParse(t, ".62581", 62581000)
	testParse(t, ".625819", 62581900)
	testParse(t, ".6258192", 62581920)
	testParse(t, ".62518192", 62518192)

	// zero padded decimals up to 8 places
	testParse(t, "99.00000000", 9900000000)
	testParse(t, "99.10000000", 9910000000)
	testParse(t, "99.62581920", 9962581920)
	testParse(t, "99.62581900", 9962581900)
	testParse(t, "99.62580000", 9962580000)
	testParse(t, "99.6258100", 9962581000)
	testParse(t, "99.625800", 9962580000)
	testParse(t, "99.250000", 9925000000)
	testParse(t, "99.62500", 9962500000)

	// extra decimal digits (more than 8)
	testParse(t, "18.000000000000", 1800000000)
	testParse(t, "18.625181929999", 1862518192)
	testParse(t, "18.999999999999", 1899999999)
	testParse(t, "18.999999999999999999999999999999999", 1899999999)

	// bugs due to checking max decimal-part instead of counting decimal digits
	// (this leads to parsing these as 13.99999999 and 13.19999999)
	testParse(t, "13.000000009999999999999999999999999", 1300000000)
	testParse(t, "13.000000019999999999999999999999999", 1300000001)
	testParse(t, "13.000100001", 1300010000)

	// max money
	testParse(t, "9999999999.99999999", MaxMoney-1)
	testParse(t, "10000000000.00000000", MaxMoney)

	// excessive zero-padding, beyond MaxMoney
	testParse(t, "00000000000000010000000000.00000000", MaxMoney)
}

func TestParseErrors(t *testing.T) {
	// greater than max money
	_, err := ParseKoinu("10000000000.00000001") // MaxMoney+1
	if err == nil {
		t.Errorf("greater than max-money, should fail to parse: 10000000000.00000001")
	}
	_, err = ParseKoinu("10000000001") // integer part + 1
	if err == nil {
		t.Errorf("greater than max-money, should fail to parse: 10000000001")
	}
	_, err = ParseKoinu("100000000000000000000000") // excessive length
	if err == nil {
		t.Errorf("greater than max-money, should fail to parse: 100000000000000000000001")
	}
}

func testParse(t *testing.T, amt string, expect int64) {
	val, err := ParseKoinu(amt)
	if err != nil {
		t.Errorf("parse error: %v", err)
	}
	if val != Koinu(expect) {
		t.Errorf("parsed incorrect value: %v (expecting %v)", int64(val), expect)
	}
}
