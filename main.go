package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

/*
implement Elliptic Curve Diffie-Hellman (ECDH) for key exchange.
The code generates public-private key pairs for two parties,
exchanges public keys, and then computes a shared secret.
*/

// ecdh function computes the shared secret using a private key and a public key
func ecdh(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Performing the ECDH key exchange
	x, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	if x == nil {
		return nil, fmt.Errorf("failed to generate shared secret")
	}

	// Returning the X coordinate of the resulting point
	return x.Bytes(), nil
}

func main() {
	// Generating a private-public key pair for Alice
	privateKeyAlice, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		return
	}

	// Generating a private-public key pair for Bob
	privateKeyBob, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		return
	}

	// Alice computes the shared secret using her private key and Bob's public key
	secretAlice, err := ecdh(privateKeyAlice, privateKeyBob.Public().(*ecdsa.PublicKey))
	if err != nil {
		fmt.Println("Failed to compute shared secret:", err)
		return
	}

	// Bob computes the shared secret using his private key and Alice's public key
	secretBob, err := ecdh(privateKeyBob, privateKeyAlice.Public().(*ecdsa.PublicKey))
	if err != nil {
		fmt.Println("Failed to compute shared secret:", err)
		return
	}

	// Displaying the shared secrets computed by Alice and Bob
	fmt.Printf("Shared Secret (Alice): %x\n", secretAlice)
	fmt.Printf("Shared Secret (Bob): %x\n", secretBob)
}
