package main

import (
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	SIGN_PAYLOAD = "Test123123!"
)

func main() {
	// Generate secret key instance.
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated secret key: %s\n", hexutil.Encode(crypto.FromECDSA(sk)))
	fmt.Printf("Sign payload: %s\n", SIGN_PAYLOAD)

	sign, err := signPersonal([]byte(SIGN_PAYLOAD), sk)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature: %s\n\n", hexutil.Encode(sign))

	// Try to recover this.
	pk_recovered, err := recover(sign, []byte(SIGN_PAYLOAD))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Original public key:  %s\n", hexutil.Encode(crypto.FromECDSAPub(&sk.PublicKey)))
	fmt.Printf("Recovered public key: %s\n", hexutil.Encode(crypto.FromECDSAPub(pk_recovered)))

	os.Exit(0)
}

// signPersonal signs a payload using given secret key.
func signPersonal(payload []byte, sk *ecdsa.PrivateKey) (signature []byte, err error) {
	digest := signPersonalDigest(payload)
	signature, err = crypto.Sign(digest, sk)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// signPersonalDigest hashes the given payload with eth.personal.sign struct.
// NOTE: `len(data)` is byte count, not Unicode codepoint count.
// i.e.    `len("🐴") == 4`
func signPersonalDigest(data []byte) []byte {
	messsage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(messsage))
}

// recover recovers the public key from the given signature and payload.
func recover(signature, message []byte) (pubkey *ecdsa.PublicKey, err error) {
	digest := signPersonalDigest(message)
	pubkey_bytes, err := crypto.Ecrecover(digest, signature)
	if err != nil {
		return nil, err
	}

	return crypto.UnmarshalPubkey(pubkey_bytes)
}
