package omniauth

import (
	"context"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/m-mizutani/goerr"
)

type googleOAuth2 struct {
	oauth2Client oauth2
	callbackPath string
	verifier     *oidc.IDTokenVerifier
}

type googleOAuthUserInfo struct {
	Email         emailAddress `json:"email"`
	EmailVerified bool         `json:"email_verified"`
	HD            string       `json:"hd"`
	Locale        string       `json:"locale"`
	Name          string       `json:"name"`
	FamilyName    string       `json:"family_name"`
	GivenName     string       `json:"given_name"`
	Picture       string       `json:"picture"`
	Sub           string       `json:"sub"`
}

func (x *googleOAuth2) Validate() error {
	return nil
}

func WithGoogleOAuth2(clientID, clientSecret, callback string) Option {
	return func(n *OmniAuth) error {
		uri, err := url.Parse(callback)
		if err != nil {
			return goerr.Wrap(err, "OAuth2 callback URI")
		}

		provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
		if err != nil {
			return goerr.Wrap(err)
		}

		g := &googleOAuth2{
			oauth2Client: newOAuth2(
				oauth2ClientID(clientID),
				oauth2ClientSecret(clientSecret),
				URI(callback),
			),
			callbackPath: uri.Path,
			verifier:     provider.Verifier(&oidc.Config{ClientID: clientID}),
		}
		if err := g.Validate(); err != nil {
			return err
		}

		n.google = g
		return nil
	}
}

const (
	googleAuthEndpoint     URI = "https://accounts.google.com/o/oauth2/auth"
	googleTokenEndpoint    URI = "https://oauth2.googleapis.com/token"
	googleUserInfoEndpoint URI = "https://openidconnect.googleapis.com/v1/userinfo"

	googleOAuthScopeUserEmail   = "https://www.googleapis.com/auth/userinfo.email"
	googleOAuthScopeUserProfile = "https://www.googleapis.com/auth/userinfo.profile"
)

func (x *googleOAuth2) Auth(w http.ResponseWriter, r *http.Request) (*User, error) {
	if r.Method == http.MethodGet && r.URL.Path == x.callbackPath {
		return x.callback(w, r)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieCallback,
		Value:    r.URL.Path,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
	})

	x.redirectToAuthEndpoint(w, r)
	return nil, nil
}

func (x *googleOAuth2) redirectToAuthEndpoint(w http.ResponseWriter, r *http.Request) {
	scopes := []string{
		googleOAuthScopeUserEmail,
		googleOAuthScopeUserProfile,
	}

	w.Header().Add("Location", string(x.oauth2Client.AuthURI(googleAuthEndpoint, scopes)))
	w.WriteHeader(http.StatusFound)
	w.Write([]byte("redirect to google auth endpoint"))
}

func (x *googleOAuth2) callback(w http.ResponseWriter, r *http.Request) (*User, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, goerr.Wrap(ErrInvalidGoogleOAuth2Proc, "no code in redirect URI")
	}

	ctx := r.Context()
	accessToken, err := x.oauth2Client.GetToken(ctx, googleTokenEndpoint, oauth2Code(code))
	if err != nil {
		return nil, err
	}

	token, err := x.verifier.Verify(r.Context(), accessToken.IDToken)
	if err != nil {
		return nil, err
	}

	var userInfo googleOAuthUserInfo
	if err := token.Claims(&userInfo); err != nil {
		return nil, err
	}

	return &User{
		Provider: googleOAuth2Provider,
		Name:     userInfo.Name,
		ID:       userInfo.Sub,
		Email:    userInfo.Email,
	}, nil
}
