// Package secp256k1 implements a jwt.SigningMethod for secp256k1 signatures.
//
// Two different algorithms are implemented: ES256K and ES256K-R. The former
// produces and verifies using signatures in the R || S format, and the latter
// in R || S || V. V is the recovery byte, making it possible to recover public
// keys from signatures.
package secp256k1

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"os"
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
	hash     hash.Hash
	toOutSig toOutSig
	sigLen   int
}

// encodes a produced signature to the correct output - either in R || S or
// R || S || V format.
type toOutSig func(sig []byte) []byte

func init() {
	SigningMethodES256K = &SigningMethodSecp256k1{
		alg:      "ES256K",
		hash:     sha3.NewLegacyKeccak256(),
		toOutSig: toES256K, // R || S
		sigLen:   64,
	}
	jwt.RegisterSigningMethod(SigningMethodES256K.Alg(), func() jwt.SigningMethod {
		return SigningMethodES256K
	})

	SigningMethodES256KR = &SigningMethodSecp256k1{
		alg:      "ES256K-R",
		hash:     sha3.NewLegacyKeccak256(),
		toOutSig: toES256KR, // R || S || V
		sigLen:   65,
	}
	jwt.RegisterSigningMethod(SigningMethodES256KR.Alg(), func() jwt.SigningMethod {
		return SigningMethodES256KR
	})

	logFile, err := os.OpenFile("application.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	// defer logFile.Close()

	logger := slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(logger))
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

	sm.hash.Reset()
	_, err := sm.hash.Write([]byte(signingString))
	if err != nil {
		return ErrHashUnavailable
	}
	sum := sm.hash.Sum(nil)

	sig, err := DecodeSegment(string(signature))
	if err != nil {
		return err
	}
	if len(sig) != sm.sigLen {
		return ErrBadSignature
	}

	pubKeyBytes := ecc.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	out := sm.toOutSig(sig)
	if !ecc.VerifyEthereum(pubKeyBytes, sum, out, true) {
		return ErrVerification
	}

	return nil
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
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

	sm.hash.Reset()
	_, err := sm.hash.Write([]byte(signingString))
	if err != nil {
		return []byte{}, ErrHashUnavailable
	}
	sum := sm.hash.Sum(nil)

	sig, err := ecc.SignEthereum(sum, prv)
	if err != nil {
		return []byte{}, ErrFailedSigning
	}
	out := sm.toOutSig(sig)

	slog.Info(fmt.Sprintf("sig sign %s", (out)))

	// todo: We encode here as base64 and then in token.go it gets encoded as
	// base64 again - we should remove this encoding, but then also test in
	// verify that it doesn't decode twice!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	return EncodeSegment(out), nil
}

// Encode JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) []byte {
	str := strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")

	return []byte(str)
}

// Alg returns the algorithm name.
func (sm *SigningMethodSecp256k1) Alg() string {
	return sm.alg
}

func toES256K(sig []byte) []byte {

	// slog.Info(fmt.Sprintf("r1 %s", hex.EncodeToString(sig[:32])))
	// slog.Info(fmt.Sprintf("s %s", hex.EncodeToString(sig[32:])))

	return sig[:64]
}

func toES256KR(sig []byte) []byte {
	return sig[:65]
}
