package test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/dogeorg/doge/bip39"
)

func TestBip39(t *testing.T) {
	// read test vectors
	tv, err := os.ReadFile("vectors.json")
	if err != nil {
		panic(err)
	}
	vec := map[string][][]string{}
	err = json.Unmarshal(tv, &vec)
	if err != nil {
		panic(err)
	}

	// The passphrase "TREZOR" is used for all vectors.
	password := "TREZOR"

	for lang, tests := range vec {
		for tno, test := range tests {
			if len(test) != 4 {
				panic("bad test-vector")
			}
			entropyHex, mnemonic, seedHex, _ := test[0], test[1], test[2], test[3] // t_xprv
			entropy, err := hex.DecodeString(entropyHex)
			if err != nil {
				panic(err)
			}
			seed, err := hex.DecodeString(seedHex)
			if err != nil {
				panic(err)
			}

			// MnemonicFromEntropy should generate the same mnemonic and seed from the entropy
			resMnemonic, resSeed, err := bip39.MnemonicFromEntropy(entropy, password, bip39.WordLists[lang], bip39.LangSpace[lang])
			if err != nil {
				t.Errorf("MnemonicFromEntropy: %v", err)
				continue
			}
			if resMnemonic != mnemonic {
				t.Errorf("test %v:%v: incorrect mnemonic::\n'%v' vs\n'%v'", lang, tno, resMnemonic, mnemonic)
			}
			if !bytes.Equal(resSeed, seed) {
				t.Errorf("test %v:%v: incorrect seed: '%v' vs '%v'", lang, tno, hex.EncodeToString(resSeed), seedHex)
			}

			// SeedFromMnemonic should generate the original seed from the mnemonic result above
			roundTripSeed, err := bip39.SeedFromMnemonic(resMnemonic, password, bip39.WordLists[lang])
			if err != nil {
				t.Errorf("SeedFromMnemonic: %v", err)
				continue
			}
			if !bytes.Equal(roundTripSeed, seed) {
				t.Errorf("test %v:%v: incorrect round-trip seed: '%v' vs '%v'", lang, tno, hex.EncodeToString(roundTripSeed), seedHex)
			}

		}
	}
}
