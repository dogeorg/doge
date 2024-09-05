package doge

import "errors"

type ChainParams struct {
	ChainName                string
	GenesisBlock             string
	P2PKH_Address_Prefix     byte
	P2SH_Address_Prefix      byte
	PKey_Prefix              byte
	Bip32_PrivKey_Prefix     uint32
	Bip32_PubKey_Prefix      uint32
	Bip32_WIF_PrivKey_Prefix string
	Bip32_WIF_PubKey_Prefix  string
}

var DogeMainNetChain ChainParams = ChainParams{
	ChainName:                "doge_main",
	GenesisBlock:             "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691",
	P2PKH_Address_Prefix:     0x1e,       // D
	P2SH_Address_Prefix:      0x16,       // 9 or A
	PKey_Prefix:              0x9e,       // Q or 6
	Bip32_PrivKey_Prefix:     0x02fac398, // dgpv
	Bip32_PubKey_Prefix:      0x02facafd, // dgub
	Bip32_WIF_PrivKey_Prefix: "dgpv",
	Bip32_WIF_PubKey_Prefix:  "dgub",
}

var DogeTestNetChain ChainParams = ChainParams{
	ChainName:                "doge_test",
	GenesisBlock:             "bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e",
	P2PKH_Address_Prefix:     0x71,       // n
	P2SH_Address_Prefix:      0xc4,       // 2
	PKey_Prefix:              0xf1,       // 9 or c
	Bip32_PrivKey_Prefix:     0x04358394, // tprv
	Bip32_PubKey_Prefix:      0x043587cf, // tpub
	Bip32_WIF_PrivKey_Prefix: "tprv",
	Bip32_WIF_PubKey_Prefix:  "tpub",
}

var DogeRegTestChain ChainParams = ChainParams{
	ChainName:                "doge_regtest",
	GenesisBlock:             "3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5",
	P2PKH_Address_Prefix:     0x6f,       // n
	P2SH_Address_Prefix:      0xc4,       // 2
	PKey_Prefix:              0xef,       //
	Bip32_PrivKey_Prefix:     0x04358394, // tprv
	Bip32_PubKey_Prefix:      0x043587cf, // tpub
	Bip32_WIF_PrivKey_Prefix: "tprv",
	Bip32_WIF_PubKey_Prefix:  "tpub",
}

// Used in tests only.
var BitcoinMainChain ChainParams = ChainParams{
	ChainName:                "btc_main",
	GenesisBlock:             "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
	P2PKH_Address_Prefix:     0x00,       // 1
	P2SH_Address_Prefix:      0x05,       // 3
	PKey_Prefix:              0x80,       // 5H,5J,5K
	Bip32_PrivKey_Prefix:     0x0488ADE4, //
	Bip32_PubKey_Prefix:      0x0488B21E, //
	Bip32_WIF_PrivKey_Prefix: "xxxx",     // TODO
	Bip32_WIF_PubKey_Prefix:  "xxxx",     // TODO
}

// Used in tests only.
var BitcoinTestChain ChainParams = ChainParams{
	ChainName:                "btc_test",
	GenesisBlock:             "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
	P2PKH_Address_Prefix:     0x00,       // 1
	P2SH_Address_Prefix:      0x05,       // 3
	PKey_Prefix:              0x80,       // 5H,5J,5K
	Bip32_PrivKey_Prefix:     0x0488ADE4, //
	Bip32_PubKey_Prefix:      0x0488B21E, //
	Bip32_WIF_PrivKey_Prefix: "xxxx",     // TODO
	Bip32_WIF_PubKey_Prefix:  "xxxx",     // TODO
}

func ChainFromTestNetFlag(isTestNet bool) *ChainParams {
	if isTestNet {
		return &DogeTestNetChain
	}
	return &DogeMainNetChain
}

// CAUTION: the result is a best-guess based on the 'version byte' in
// the WIF string. Do not rely on the returned ChainParams alone
// for validation: it will fall back on DogeTestNetChain for unknown
// version bytes (so verify the version byte or bip32-prefix as well)
func ChainFromWIFString(wif string) *ChainParams {
	switch wif[0] {
	case 'D', '9', 'A', 'Q', '6', 'd':
		// FIXME: '9' is ambiguous, check 2nd character over the entire range.
		return &DogeMainNetChain
	case 'n', '2', 'c', 't': // also '9'
		return &DogeTestNetChain
	case '1', '3', '5':
		return &BitcoinMainChain
	default:
		return &DogeTestNetChain
	}
}

// CAUTION: the result is a best-guess based on the 'version byte' in
// the decoded WIF data. Do not rely on the returned ChainParams alone
// for validation: it will fall back on DogeTestNetChain for unknown
// version bytes (so verify the version byte or bip32-prefix as well)
func ChainFromWIFPrefix(bytes []byte, allowNonDoge bool) *ChainParams {
	if len(bytes) == 0 {
		return &DogeTestNetChain // fallback
	}
	switch bytes[0] {
	case 0x1e, 0x16, 0x9e, 0x02:
		return &DogeMainNetChain
	case 0x71, 0xc4, 0xf1:
		return &DogeTestNetChain
	case 0x04:
		if allowNonDoge {
			// 0x04 is ambigous (DogeTestNetChain vs BitcoinMainChain)
			if len(bytes) > 1 && bytes[1] == 0x88 {
				return &BitcoinMainChain
			}
		}
		return &DogeTestNetChain
	case 0x6f, 0xef:
		return &DogeRegTestChain
	case 0x00, 0x05, 0x80:
		if allowNonDoge {
			return &BitcoinMainChain
		}
	}
	return &DogeTestNetChain // fallback
}

func ChainFromBip32Version(version uint32, allowNonDoge bool) (bool, *ChainParams) {
	switch version {
	case 0x02fac398, 0x02facafd: // dgpv, dgub
		return true, &DogeMainNetChain
	case 0x04358394, 0x043587cf: // tprv, tpub
		if allowNonDoge {
			return true, &BitcoinTestChain
		}
	case 0x0488ADE4, 0x0488B21E: // bitcoin mainnet
		if allowNonDoge {
			return true, &BitcoinMainChain
		}
	}
	return false, &DogeTestNetChain // fallback
}

func ChainFromGenesisHash(hash string) (*ChainParams, error) {
	if hash == DogeMainNetChain.GenesisBlock {
		return &DogeMainNetChain, nil
	}
	if hash == DogeTestNetChain.GenesisBlock {
		return &DogeTestNetChain, nil
	}
	if hash == DogeRegTestChain.GenesisBlock {
		return &DogeRegTestChain, nil
	}
	return nil, errors.New("ChainFromGenesisHash: unrecognised chain: " + hash)
}
