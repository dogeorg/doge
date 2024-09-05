package doge

import (
	"testing"
)

func TestExtract(t *testing.T) {
	extECT(t,
		"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
		"L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW",
		"15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma",
	)
	extECT(t,
		"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
		"L5BmPijJjrKbiUfG4zbiFKNqkvuJ8usooJmzuD7Z8dkRoTThYnAT",
		"19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh",
	)
	extECT(t,
		"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
		"KyFAjQ5rgrKvhXvNMtFB5PCSKUYD1yyPEe3xr3T34TZSUHycXtMM",
		"1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj",
	)
	extECT(t,
		"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
		"L43t3od1Gh7Lj55Bzjj1xDAgJDcL7YFo2nEcNaMGiyRZS1CidBVU",
		"1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x",
	)
	extECT(t,
		"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
		"KwjQsVuMjbCP2Zmr3VaFaStav7NvevwjvvkqrWd5Qmh1XVnCteBR",
		"1LjmJcdPnDHhNTUgrWyhLGnRDKxQjoxAgt",
	)
	extECT(t,
		"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
		"Kybw8izYevo5xMh1TK7aUr7jHFCxXS1zv8p3oqFz3o2zFbhRXHYs",
		"1LZiqrop2HGR4qrH1ULZPyBpU6AUP49Uam",
	)
}

func extECT(t *testing.T, ext_key string, ec_key string, p2pkh string) {
	key, err := ECPrivKeyFromBip32WIF(ext_key, nil)
	if err != nil {
		t.Errorf("ExtractECPrivKeyFromBip32: %v", err)
	}
	if key != ec_key {
		t.Errorf("ECPrivKeyFromBip32WIF: EC Key doesn't match: %s vs %s", key, ec_key)
	}
	addr, err := P2PKHFromECPrivKeyWIF(key)
	if err != nil {
		t.Errorf("P2PKHFromECPrivKeyWIF: %v", err)
	}
	if addr != Address(p2pkh) {
		t.Errorf("P2PKHFromECPrivKeyWIF: Address doesn't match: %s vs %s", addr, p2pkh)
	}
}
