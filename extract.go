package doge

import "fmt"

// Given a Bip32 Extended Private Key WIF, extract the WIF-encoded EC Private Key.
// chain is optional, will auto-detect if nil.
func ECPrivKeyFromBip32WIF(ext_key_wif string, chain *ChainParams) (ec_privkey_wif string, err error) {
	bkey, err := DecodeBip32WIF(ext_key_wif, nil)
	if err != nil {
		return "", err
	}
	if chain == nil {
		chain = bkey.chain
	}
	if !bkey.IsPrivate() {
		bkey.Clear() // clear key for security.
		return "", fmt.Errorf("DecodeBip32WIF: not a BIP32 WIF private key (wrong prefix)")
	}
	priv, err := bkey.GetECPrivKey()
	if err != nil {
		bkey.Clear() // clear key for security.
		return "", err
	}
	bkey.Clear() // clear key for security.
	if !ECKeyIsValid(priv) {
		return "", fmt.Errorf("ECPrivKeyFromBip32WIF: invalid EC key (zero or >= N)")
	}
	ret, err := EncodeECPrivKeyWIF(priv, chain), nil
	memZero(priv)
	return ret, err
}

func P2PKHFromECPrivKeyWIF(ec_priv_key_wif string) (p2pkh Address, err error) {
	ec_pk, chain, err := DecodeECPrivKeyWIF(ec_priv_key_wif, nil)
	if err != nil {
		return "", err
	}
	ec_pub_compressed := ECPubKeyFromECPrivKey(ec_pk)
	clear(ec_pk) // clear key for security.
	return PubKeyToP2PKH(ec_pub_compressed, chain)
}

func memZero(to []byte) {
	for i := range to {
		to[i] = 0
	}
}
