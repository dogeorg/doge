package test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dogeorg/doge/bip39"
	"golang.org/x/text/unicode/norm"
)

func TestBip39_JP(t *testing.T) {
	// read test vectors
	tv, err := os.ReadFile("test_JP_BIP39.json")
	if err != nil {
		panic(err)
	}
	tests := []map[string]string{}
	err = json.Unmarshal(tv, &tests)
	if err != nil {
		panic(err)
	}

	wordlist := bip39.JapaneseWordList
	lang := "japanese"
	space := bip39.IdeographicSpace

	for tno, test := range tests {
		entropyHex, mnemonic, password, seedHex := test["entropy"], test["mnemonic"], test["passphrase"], test["seed"] // "bip32_xprv"

		// SeedFromMnemonic should generate the seed from the mnemonic
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			panic(err)
		}
		outSeed, err := bip39.SeedFromMnemonic(strings.Split(mnemonic, space), password, wordlist)
		if err != nil {
			t.Errorf("SeedFromMnemonic: %v", err)
			continue
		}
		if !bytes.Equal(outSeed, seed) {
			t.Errorf("test %v:%v: SeedFromMnemonic: incorrect seed: '%v' vs '%v'", lang, tno, hex.EncodeToString(outSeed), seedHex)
		}

		// MnemonicFromEntropy should generate the same mnemonic and seed from the entropy
		entropy, err := hex.DecodeString(entropyHex)
		if err != nil {
			panic(err)
		}
		resMnemonic, err := bip39.MnemonicFromEntropy(entropy, wordlist)
		if err != nil {
			t.Errorf("MnemonicFromEntropy: %v", err)
			continue
		}
		resSeed, err := bip39.SeedFromMnemonic(resMnemonic, password, wordlist)
		if err != nil {
			t.Errorf("SeedFromMnemonic: %v", err)
			continue
		}
		if !bytes.Equal(resSeed, seed) {
			t.Errorf("test %v:%v: MnemonicFromEntropy: incorrect seed: '%v' vs '%v'", lang, tno, hex.EncodeToString(outSeed), seedHex)
		}
		resMnemonicNFKD := norm.NFKD.String(strings.Join(resMnemonic, " ")) // returned mnemonic is normalized
		srcMnemonicNFKD := norm.NFKD.String(mnemonic)                       // test-vector mnemonics are de-normalized
		if resMnemonicNFKD != srcMnemonicNFKD {
			t.Errorf("test %v:%v: MnemonicFromEntropy: incorrect mnemonic:\n'%v' vs\n'%v'", lang, tno, resMnemonicNFKD, srcMnemonicNFKD)
		}
	}
}
