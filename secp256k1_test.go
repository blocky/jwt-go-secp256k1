package secp256k1_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/dustinxie/ecc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	secp256k1 "github.com/blocky/jwt-go-secp256k1"
)

func TestGeneration(t *testing.T) {

	key, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
	require.NoError(t, err)

	t.Run("ES256K", func(t *testing.T) {
		token := jwt.NewWithClaims(
			secp256k1.SigningMethodES256K,
			jwt.MapClaims{"iat": int64(12387687632)},
		)

		sString, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("failed signing token: %s", err)
		}

		_, err = jwt.Parse(sString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*secp256k1.SigningMethodSecp256k1); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			return &key.PublicKey, nil
		})

		if err != nil {
			t.Fatalf("failed verifying signed token")
		}
	})

	t.Run("ES256K-R", func(t *testing.T) {
		token := jwt.NewWithClaims(
			secp256k1.SigningMethodES256KR,
			jwt.MapClaims{"iat": int64(12387687632)},
		)

		sString, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("failed signing token: %s", err)
		}

		_, err = jwt.Parse(sString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*secp256k1.SigningMethodSecp256k1); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			return &key.PublicKey, nil
		})

		if err != nil {
			t.Fatalf("failed verifying signed token")
		}
	})

}
