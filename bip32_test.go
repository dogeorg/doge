package doge

import (
	"testing"
)

type bip32fix struct {
	XPub    string
	XPrv    string
	PrvWif  string
	PubAddr string
	Fpr     uint32
	Path    []uint32
}

// https://en.bitcoin.it/wiki/BIP_0032_TestVectors
// NOTE: in these test vectors, the (fpr) shown under Identifier is
// the fingerprint for *this* key's public key, not the fingerprint
// for the parent key as used in the Bip32 Serialization Format.

// Test vector 1

const bip32seed = "000102030405060708090a0b0c0d0e0f"

var bip32fixtures = []bip32fix{
	{
		"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
		"L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW",
		"15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma",
		0x3442193e, // (fpr)
		[]uint32{}, // [m]
	},
	{
		"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
		"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
		"L5BmPijJjrKbiUfG4zbiFKNqkvuJ8usooJmzuD7Z8dkRoTThYnAT",
		"19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh",
		0x5c1bd648,                // (fpr)
		[]uint32{HardenedKey + 0}, // [m/0']
	},
	{
		"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
		"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
		"KyFAjQ5rgrKvhXvNMtFB5PCSKUYD1yyPEe3xr3T34TZSUHycXtMM",
		"1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj",
		0xbef5a2f9,                   // (fpr)
		[]uint32{HardenedKey + 0, 1}, // [m/0'/1]
	},
	{
		"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
		"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
		"L43t3od1Gh7Lj55Bzjj1xDAgJDcL7YFo2nEcNaMGiyRZS1CidBVU",
		"1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x",
		0xee7ab90c,                                    // (fpr)
		[]uint32{HardenedKey + 0, 1, HardenedKey + 2}, // [m/0'/1/2']
	},
	{
		"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
		"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
		"KwjQsVuMjbCP2Zmr3VaFaStav7NvevwjvvkqrWd5Qmh1XVnCteBR",
		"1LjmJcdPnDHhNTUgrWyhLGnRDKxQjoxAgt",
		0xd880d7d8,                                       // (fpr)
		[]uint32{HardenedKey + 0, 1, HardenedKey + 2, 2}, // [m/0'/1/2'/2]
	},
	{
		"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
		"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
		"Kybw8izYevo5xMh1TK7aUr7jHFCxXS1zv8p3oqFz3o2zFbhRXHYs",
		"1LZiqrop2HGR4qrH1ULZPyBpU6AUP49Uam",
		0xd69aa102,                                                   // (fpr)
		[]uint32{HardenedKey + 0, 1, HardenedKey + 2, 2, 1000000000}, // [m/0'/1/2'/2/1000000000]
	},
}

func TestDecodeBip32(t *testing.T) {
	for _, fix := range bip32fixtures {
		child_no := uint32(0)
		if len(fix.Path) > 0 {
			child_no = fix.Path[len(fix.Path)-1]
		}
		key_depth := byte(len(fix.Path))

		// decode private key
		priv, err := DecodeBip32WIF(fix.XPrv, nil)
		if err != nil {
			t.Error(err)
		} else {
			// check depth and child_number.
			if priv.depth != key_depth {
				t.Errorf("Bip32WIF: XPrv has wrong key depth: %v vs %v for %v", priv.depth, key_depth, fix.Path)
			}
			if priv.child_number != child_no {
				t.Errorf("Bip32WIF: XPrv has wrong child_number: %v vs %v for %v", priv.child_number, child_no, fix.Path)
			}
			// check round-trip.
			priv_wif := priv.EncodeWIF()
			if priv_wif != fix.XPrv {
				t.Errorf("Bip32WIF: XPrv did not round-trip: %v vs %v for %v", priv_wif, fix.XPrv, fix.Path)
			}
		}

		// decode public key
		pub, err := DecodeBip32WIF(fix.XPub, nil)
		if err != nil {
			t.Error(err)
		} else {
			// check depth and child_number.
			if pub.depth != key_depth {
				t.Errorf("Bip32WIF: XPub has wrong key depth: %v vs %v for %v", pub.depth, key_depth, fix.Path)
			}
			if pub.child_number != child_no {
				t.Errorf("Bip32WIF: XPub has wrong child_number: %v vs %v for %v", pub.child_number, child_no, fix.Path)
			}
			// check round-trip.
			pub_wif := pub.EncodeWIF()
			if pub_wif != fix.XPub {
				t.Errorf("Bip32WIF: XPub did not round-trip: %v vs %v for %v", pub_wif, fix.XPub, fix.Path)
			}
		}
	}
}

func TestBip32DerivePrivate(t *testing.T) {
	// https://en.bitcoin.it/wiki/BIP_0032 (Test Vectors)
	// https://en.bitcoin.it/wiki/BIP_0032_TestVectors

	master, err := Bip32MasterFromSeed(hx2b(bip32seed), &BitcoinMainChain)
	if err != nil {
		t.Errorf("Bip32MasterFromSeed: %v", err)
	} else {
		m1wif := master.EncodeWIF()
		if m1wif != bip32fixtures[0].XPrv {
			t.Errorf("Bip32MasterFromSeed: wrong xprv: %v vs %v", m1wif, bip32fixtures[0].XPrv)
		}
	}

	for _, fix := range bip32fixtures {
		child, err := master.DeriveChild(fix.Path)
		if err != nil {
			t.Errorf("DeriveChild: %v", err)
			continue
		}

		// check XPrv.
		privWIF := child.EncodeWIF()
		if privWIF != fix.XPrv {
			t.Errorf("DeriveChild: wrong xprv: %v vs %v for %v", privWIF, fix.XPrv, fix.Path)
		}

		// check XPub.
		pubWIF := child.Public().EncodeWIF()
		if pubWIF != fix.XPub {
			t.Errorf("DeriveChild: wrong xpub: %v vs %v for %v", pubWIF, fix.XPub, fix.Path)
		}

		// check fingerprint of THIS key (not parent fingerprint as in Bip32 WIF)
		fingerprint := child.ThisKeyFingerprint()
		if fingerprint != fix.Fpr {
			t.Errorf("DeriveChild: wrong fingerprint: 0x%08x vs 0x%08x for %v", fingerprint, fix.Fpr, fix.Path)
		}

		// check Secret Key.
		privKey, err := child.GetECPrivKey()
		if err != nil {
			t.Errorf("GetECPrivKey: %v", err)
		} else {
			privKeyWIF := EncodeECPrivKeyWIF(privKey, child.ChainParams())
			if privKeyWIF != fix.PrvWif {
				t.Errorf("DeriveChild: wrong secret key: %v vs %v for %v", privKeyWIF, fix.PrvWif, fix.Path)
			}
		}

		// check Address.
		pubKey, err := PubKeyToP2PKH(child.GetECPubKey(), child.ChainParams())
		if err != nil {
			t.Errorf("PubKeyToP2PKH: %v", err)
		} else if pubKey != Address(fix.PubAddr) {
			t.Errorf("DeriveChild: wrong public address: %v vs %v for %v", pubKey, fix.PubAddr, fix.Path)
		}
	}
}

func TestBip32DerivePublic(t *testing.T) {
	master, err := Bip32MasterFromSeed(hx2b(bip32seed), &BitcoinMainChain)
	if err != nil {
		t.Errorf("Bip32MasterFromSeed: %v", err)
	} else {
		m1wif := master.EncodeWIF()
		if m1wif != bip32fixtures[0].XPrv {
			t.Errorf("Bip32MasterFromSeed: wrong xprv: %v vs %v", m1wif, bip32fixtures[0].XPrv)
		}
	}

	for _, fix := range bip32fixtures {
		// only test non-hardened final key derivations (cannot publically derive from hardened keys)
		last := len(fix.Path) - 1
		if len(fix.Path) > 0 && fix.Path[last] < HardenedKey {
			// first, derive up to the 2nd-last key using private ckd
			prior, err := master.DeriveChild(fix.Path[:last])
			if err != nil {
				t.Errorf("DeriveChild: %v", err)
			}
			// derive the final key using public derivation
			child, err := prior.Public().PublicCKD(fix.Path[last])
			if err != nil {
				t.Errorf("DeriveChild: %v", err)
			}

			// check XPub.
			pubWIF := child.EncodeWIF()
			if pubWIF != fix.XPub {
				t.Errorf("DeriveChild: wrong xpub: %v vs %v for %v", pubWIF, fix.XPub, fix.Path)
			}

			// check fingerprint of THIS key (not parent fingerprint as in Bip32 WIF)
			fingerprint := child.ThisKeyFingerprint()
			if fingerprint != fix.Fpr {
				t.Errorf("DeriveChild: wrong fingerprint: 0x%08x vs 0x%08x for %v", fingerprint, fix.Fpr, fix.Path)
			}

			// check Address.
			pubKey, err := PubKeyToP2PKH(child.GetECPubKey(), child.ChainParams())
			if err != nil {
				t.Errorf("PubKeyToP2PKH: %v", err)
			} else if pubKey != Address(fix.PubAddr) {
				t.Errorf("DeriveChild: wrong public address: %v vs %v for %v", pubKey, fix.PubAddr, fix.Path)
			}
		}
	}
}
