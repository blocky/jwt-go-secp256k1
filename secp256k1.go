// Package secp256k1 implements a jwt.SigningMethod for secp256k1 signatures.
//
// Two different algorithms are implemented: ES256K and ES256K-R. The former
// produces and verifies using signatures in the R || S format, and the latter
// in R || S || V. V is the recovery byte, making it possible to recover public
// keys from signatures.
package secp256k1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/dustinxie/ecc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/sha3"
)

// ES256K and ES256K-R algorithms. uPort uses SigningMethodES256KR.
var (
	// SigningMethodES256K produces and accepts 256-bit signatures using the
	// secp256k1 curve.
	// The signature is in R || S format.
	SigningMethodES256K *SigningMethodSecp256k1
	// SigningMethodES256KR produces and accepts 264-bit signatures using the
	// secp256k1 curve.
	// The signature is in R || S || V format, with V being the recovery byte.
	SigningMethodES256KR *SigningMethodSecp256k1
)

// SigningMethodSecp256k1 is the implementation of jwt.SigningMethod.
type SigningMethodSecp256k1 struct {
	alg      string
	newHash  func() hash.Hash
	toOutSig toOutSig
	sigLen   int
}

// encodes a produced signature to the correct output - either in R || S or
// R || S || V format.
type toOutSig func(sig []byte) []byte

func init() {
	SigningMethodES256K = &SigningMethodSecp256k1{
		alg:      "ES256K",
		newHash:  sha3.NewLegacyKeccak256,
		toOutSig: toES256K, // R || S
		sigLen:   64,
	}
	jwt.RegisterSigningMethod(SigningMethodES256K.Alg(), func() jwt.SigningMethod {
		return SigningMethodES256K
	})

	SigningMethodES256KR = &SigningMethodSecp256k1{
		alg:      "ES256K-R",
		newHash:  sha3.NewLegacyKeccak256,
		toOutSig: toES256KR, // R || S || V
		sigLen:   65,
	}
	jwt.RegisterSigningMethod(SigningMethodES256KR.Alg(), func() jwt.SigningMethod {
		return SigningMethodES256KR
	})

	// logFile, err := os.OpenFile("application.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	// if err != nil {
	// 	panic(err)
	// }
	// // defer logFile.Close()
	//
	// logger := slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo})
	// slog.SetDefault(slog.New(logger))
}

// Errors returned on different problems.
var (
	ErrWrongKeyFormat  = errors.New("wrong key type")
	ErrBadSignature    = errors.New("bad signature")
	ErrVerification    = errors.New("signature verification failed")
	ErrFailedSigning   = errors.New("failed generating signature")
	ErrHashUnavailable = errors.New("hasher unavailable")
)

// Verify verifies a secp256k1 signature in a JWT. The type of key has to be
// *ecdsa.PublicKey.
//
// Verify it is a secp256k1 key before passing, otherwise it will validate with
// that type of key instead. This can be done using ethereum's crypto package.
func (sm *SigningMethodSecp256k1) Verify(
	signingString string,
	signature []byte,
	key interface{},
) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrWrongKeyFormat
	}

	h := sm.newHash()
	_, err := h.Write([]byte(signingString))
	if err != nil {
		return ErrHashUnavailable
	}
	sum := h.Sum(nil)

	pubKeyBytes := ecc.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	if !ecc.VerifyEthereum(pubKeyBytes, sum, signature[:64], true) {
		return ErrVerification
	}

	// todo: add a test for ecrecover, but just for K-R"

	return nil
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

func UnmarshalECDSAPublicKey(data []byte, obj any) error {
	sk, ok := obj.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an ECDSA public key")
	}

	if sk.Curve != nil && sk.Curve != ecc.P256k1() {
		return fmt.Errorf("invalid curve")
	}

	sk.Curve = ecc.P256k1()
	sk.X, sk.Y = elliptic.Unmarshal(sk.Curve, data)
	return nil
}

// Sign produces a secp256k1 signature for a JWT. The type of key has
// to be *PrivateKey.
func (sm *SigningMethodSecp256k1) Sign(
	signingString string,
	key interface{},
) (
	[]byte,
	error,
) {
	prv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return []byte{}, ErrWrongKeyFormat
	}

	h := sm.newHash()
	_, err := h.Write([]byte(signingString))
	if err != nil {
		return []byte{}, ErrHashUnavailable
	}
	sum := h.Sum(nil)

	sig, err := ecc.SignEthereum(sum, prv)
	if err != nil {
		return []byte{}, ErrFailedSigning
	}
	out := sm.toOutSig(sig)

	// slog.Info(fmt.Sprintf("r    %s", hex.EncodeToString(out[:32])))
	// slog.Info(fmt.Sprintf("s    %s", hex.EncodeToString(out[32:])))
	// slog.Info(fmt.Sprintf("sum  %s", hex.EncodeToString(sum)))

	// address := gethCrypto.PubkeyToAddress(prv.PublicKey)
	// slog.Info(fmt.Sprintf("original  : %s", address.Hex()))
	//
	// expandedSig := out
	// slog.Info(fmt.Sprintf("last bit  : %v", expandedSig[len(expandedSig)-1]))
	// recovered, err := gethCrypto.Ecrecover(sum, expandedSig)
	// if err != nil {
	// 	return nil, fmt.Errorf("recovering public key: %w", err)
	// }
	//
	// var pub ecdsa.PublicKey
	// _ = UnmarshalECDSAPublicKey(recovered, &pub)
	// address = gethCrypto.PubkeyToAddress(pub)
	// slog.Info(fmt.Sprintf("recovered : %s", address.Hex()))

	return out, nil
}

// Alg returns the algorithm name.
func (sm *SigningMethodSecp256k1) Alg() string {
	return sm.alg
}

func toES256K(sig []byte) []byte {
	return sig[:64]
}

func toES256KR(sig []byte) []byte {
	return sig[:65]
}
