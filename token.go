package omniauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/m-mizutani/goerr"
)

func WithJwtHandler(issuer, secret string, expiresAfter time.Duration) Option {
	return func(n *OmniAuth) error {
		n.jwt = newJwtHandler(issuer, tokenSecret(secret), expiresAfter)
		return nil
	}
}

type jwtHandler struct {
	issuer       string
	secret       tokenSecret
	expiresAfter time.Duration
}

func newJwtHandler(issuer string, secret tokenSecret, expiresAfter time.Duration) *jwtHandler {
	return &jwtHandler{
		issuer:       issuer,
		secret:       secret,
		expiresAfter: expiresAfter,
	}
}

type jwtClaims struct {
	User
	jwt.RegisteredClaims
}

func (x *jwtHandler) verifyToken(ssnToken sessionToken, now time.Time) (*User, error) {
	fmt.Println("verifying", ssnToken)
	parsed, err := jwt.ParseWithClaims(string(ssnToken), &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, goerr.Wrap(ErrInvalidToken, "unexpected signing method").With("alg", token.Header["alg"])
		}

		return []byte(x.secret), nil
	})
	if err != nil {
		fmt.Println("error!!!")
		return nil, ErrInvalidToken.Wrap(err)
	}

	if !parsed.Valid {
		return nil, goerr.Wrap(ErrInvalidToken, "parse failed")
	}

	claims, ok := parsed.Claims.(*jwtClaims)
	if !ok {
		return nil, goerr.Wrap(ErrInvalidToken, "not valid")
	}

	return &claims.User, nil
}

func (x *jwtHandler) signToken(user *User, now time.Time) (string, error) {
	claims := jwtClaims{
		User: *user,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    x.issuer,
			Subject:   string(user.Provider) + ":" + user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(x.expiresAfter)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(x.secret))
	if err != nil {
		return "", goerr.Wrap(err)
	}

	return signed, nil
}
