package schnorr

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/decred/dcrd/crypto/blake256"
)

func TestGenerateExtraData(t *testing.T) {
	// Generate rfc6979ExtraDataV0
	tagDoge := blake256.Sum256([]byte("EC-Schnorr-Dogecoin"))
	acc := []string{}
	for _, b := range tagDoge {
		acc = append(acc, fmt.Sprintf("0x%02x", b))
	}
	log.Printf("rfc6979ExtraDataV0 = [32]byte{ // %v\n%v\n}", hex.EncodeToString(tagDoge[:]), strings.Join(acc, ", "))
}

func TestGenerateChallenge(t *testing.T) {
	// Generate tag for BLAKE-256 challenge hash.
	tagDoge := blake256.Sum256([]byte("Dogecoin/challenge"))
	acc := []string{}
	for _, b := range tagDoge {
		acc = append(acc, fmt.Sprintf("0x%02x", b))
	}
	log.Printf("challengeTag = [32]byte{ // %v\n%v\n}", hex.EncodeToString(tagDoge[:]), strings.Join(acc, ", "))
}
