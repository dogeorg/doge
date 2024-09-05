// Implements BIP-0039 "Mnemonic code for generating deterministic keys"
//
// https://en.bitcoin.it/wiki/BIP_0039
// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
// https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md

package bip39

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"strings"

	"github.com/dogeorg/doge/wrapped"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

// Word Lists for each language.
// Language names are from BIP39 test vectors.
var WordLists = map[string][]string{
	"english":             EnglishWordList,
	"chinese_simplified":  ChineseSimplifiedWordList,
	"chinese_traditional": ChineseTraditionalWordList,
	"czech":               CzechWordList,
	"french":              FrenchWordList,
	"italian":             ItalianWordList,
	"japanese":            JapaneseWordList,
	"korean":              KoreanWordList,
	"portuguese":          PortugueseWordList,
	"spanish":             SpanishWordList,
}

// IdeographicSpace is used to join Japanese mnemonic phrases.
const IdeographicSpace = "\u3000"

// LangSpace is the joining whitespace for each language.
var LangSpace = map[string]string{
	"english":             " ",
	"chinese_simplified":  " ",
	"chinese_traditional": " ",
	"czech":               " ",
	"french":              " ",
	"italian":             " ",
	"japanese":            IdeographicSpace,
	"korean":              " ",
	"portuguese":          " ",
	"spanish":             " ",
}

var ErrBadEntropy = errors.New("entropy must be 128-256 bits, divisible by 32")
var ErrOutOfEntropy, wrapOutOfEntropy = wrapped.New("not enough entropy available in the OS entropy pool")
var ErrWrongWord = errors.New("wrong word in mnemonic phrase: not on the wordlist")
var ErrWrongChecksum = errors.New("wrong mnemonic phrase: checksum doesn't match")
var ErrWrongLength = errors.New("wrong mnemonic length: must be 12, 15, 18, 21 or 24 words")

// GenerateRandomMnemonic generates a 12-24 word mnemonic phrase with 128-256 bits of entropy.
//
// Implements BIP-39 as described in https://en.bitcoin.it/wiki/BIP_0039
//
// The number of entropy bits must be between 128 and 256 inclusive, and divisible
// by 32 as per BIP-39.
//
// The passphrase is an optional string used to protect the seed derived from
// the mnemonic phrase (via PBKDF2)
//
// Returns the generated mnemonic phrase and the generated seed.
//
// Can return the following errors:
// ErrBadEntropy (entropy length is incorrect; expects 128,160,192,224,256)
// ErrOutOfEntropy (the OS entropy source is exhausted)
func GenerateRandomMnemonic(entropy int, passphrase string, wordlist []string) (mnemonic []string, err error) {
	if entropy < 128 || entropy > 256 || entropy%32 != 0 {
		return nil, ErrBadEntropy
	}
	entBytes := make([]byte, entropy/8)
	_, err = rand.Read(entBytes[:])
	if err != nil {
		return nil, wrapOutOfEntropy(err)
	}
	return MnemonicFromEntropy(entBytes, passphrase, wordlist)
}

// MnemonicFromEntropy converts 128-256 bits of entropy to a 12-24 word mnemonic phrase.
//
// Implements BIP-39 as described in https://en.bitcoin.it/wiki/BIP_0039
//
// The number of entropy bits must be between 128 and 256 inclusive, and divisible
// by 32 as per BIP-39.
//
// The passphrase is an optional string used to protect the seed derived from
// the mnemonic phrase (via PBKDF2)
//
// Returns the encoded mnemonic phrase and the generated seed.
//
// Can return the following errors:
// ErrBadEntropy (entropy length is incorrect; expects 16,20,24,28,32 bytes)
func MnemonicFromEntropy(entropy []byte, passphrase string, wordlist []string) (mnemonic []string, err error) {
	// The mnemonic must encode entropy [ENT] in a multiple of 32 ENT.
	// The allowed size of ENT is 128-256 ENT.
	ENT := len(entropy) * 8
	if ENT < 128 || ENT > 256 || ENT%32 != 0 {
		return nil, ErrBadEntropy
	}

	// A checksum is generated by taking the first ENT / 32 bits of its SHA256 hash.
	CS := ENT / 32                                    // range [4,8]
	checksum := sha256.Sum256(entropy)[0] >> (8 - CS) // in the low [4,8] bits

	// Next, these concatenated bits are split into groups of 11 bits,
	// each encoding a number from 0-2047, serving as an index into a wordlist.
	acc := uint32(0) // bit accumulator; current bits are in the HIGH bits
	accbits := 0     // number of bits in the accumulator [0,18]
	entpos := 0      // index into entropy
	words := []string{}
	for entpos <= len(entropy) {
		// Add entropy bytes until we have at least 11 bits (max 18=10+8)
		// These branches take the same path on every execution (for a given entropy size)
		for accbits < 11 {
			if entpos < len(entropy) {
				acc |= uint32(entropy[entpos]) << (32 - 8 - accbits) // below existing bits
				accbits += 8
			} else {
				// This checksum is appended to the end of the initial entropy.
				// This will always bring accbits up to 11 bits.
				acc |= uint32(checksum) << (32 - CS - accbits) // below existing bits
				accbits += CS
				if accbits != 11 { // cannot happen (debug assert)
					panic("bug in MnemonicFromEntropy: accbits+checksum != 11")
				}
			}
			entpos += 1
		}
		// use the top 11 bits to select a word
		words = append(words, wordlist[acc>>21])
		// discard the top 11 bits
		acc = acc << 11
		accbits -= 11
	}

	return words, nil
}

// SeedFromMnemonicPhrase derives a cryptographically random seed from a mnemonic phrase.
//
// Implements BIP-39 as described in https://en.bitcoin.it/wiki/BIP_0039
//
// This function verifies the 12-24 words are on the wordlist, and verifies the
// checksum bits included in the mnemonic phrase.
//
// Can return the following errors:
// ErrWrongLength (wrong number of words; expects 12,15,18,21,24)
// ErrWrongWord (one or more words are not on the word-list)
// ErrWrongChecksum (one or more of the words is incorrect, leading to a checksum mismatch)
func SeedFromMnemonic(mnemonic []string, passphrase string, wordlist []string) (seed []byte, err error) {
	// mnemonic input may not be NFKD
	for i, word := range mnemonic {
		mnemonic[i] = norm.NFKD.String(word)
	}
	if len(mnemonic) < 12 || len(mnemonic) > 24 || len(mnemonic)%3 != 0 { // 12,15,18,21,24
		return nil, ErrWrongLength
	}

	// look up words in the wordlist, convert back to bytes
	acc := uint32(0)
	accbits := 0
	entropy := make([]byte, 0, 33) // max size (24*11)/8 = 33
	for _, word := range mnemonic {
		index := findWord(word, wordlist)
		if index < 0 || index > 2047 {
			return nil, ErrWrongWord
		}
		accbits += 11
		acc |= uint32(index) << (32 - accbits) // below existing bits
		for accbits >= 8 {
			entropy = append(entropy, byte(acc>>24)) // take high 8 bits
			acc = acc << 8                           // discard high 8 bits
			accbits -= 8
		}
	}

	// recover the checksum from the final word-index
	CS := accbits                      // remaining bits: 4,5,6,7 (less than one byte, in high bits)
	if CS != 0 && (CS < 4 || CS > 7) { // cannot happen (debug assert)
		panic("bug in SeedFromMnemonic: remaining accbits < 4 or > 7")
	}
	var checksum byte
	if accbits != 0 {
		checksum = byte(acc >> (32 - CS)) // shift remaining 4,5,6,7 bits to low bits
	} else {
		CS = 8 // full checksum byte
		last := len(entropy) - 1
		checksum = entropy[last]  // take the last decoded byte
		entropy = entropy[0:last] // remove the last byte
	}

	// verify the checksum
	versum := sha256.Sum256(entropy)[0] >> (8 - CS) // first byte (shift to low bits)
	if checksum != versum {
		return nil, ErrWrongChecksum
	}

	// create a binary seed from the mnemonic (as described above)
	mnemonicNFKD := []byte(strings.Join(mnemonic, " "))          // mnemonic is NFKD already
	saltNFKD := norm.NFKD.Bytes([]byte("mnemonic" + passphrase)) // passphrase may not be NFKD
	seed = pbkdf2.Key(mnemonicNFKD, saltNFKD, 2048, 64, sha512.New)

	return seed, nil
}

func findWord(word string, wordlist []string) int {
	// start with the simplest thing that works
	for i, w := range wordlist {
		if w == word {
			return i
		}
	}
	return -1
}
