package doge

import "fmt"

// Given a Bip32 Extended Private Key WIF, extract the WIF-encoded EC Private Key.
func ECPrivKeyFromBip32WIF(ext_key_wif string) (ec_privkey_wif string, err error) {
	bkey, err := DecodeBip32WIF(ext_key_wif, nil)
	if err != nil {
		return "", err
	}
	priv, err := bkey.GetECPrivKey()
	if err != nil {
		bkey.Clear() // clear key for security.
		return "", err
	}
	chain := ChainFromKeyBits(bkey.keyType)
	bkey.Clear() // clear key for security.
	if !ECKeyIsValid(priv) {
		return "", fmt.Errorf("ExtractECPrivKeyFromBip32: invalid EC key (zero or >= N)")
	}
	return EncodeECPrivKeyWIF(priv, chain), nil
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
