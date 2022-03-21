package omniauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/m-mizutani/goerr"
)

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type oauth2 interface {
	authURI(authURI URI, scopes []string) URI
	getToken(ctx context.Context, uri URI, code oauth2Code) (*oauth2AccessToken, error)
	getUserInfo(ctx context.Context, uri URI, accessToken accessToken, out interface{}) error
}

type oauth2AccessToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

type oauth2Client struct {
	clientID     oauth2ClientID
	clientSecret oauth2ClientSecret
	callbackURI  URI

	httpClient httpClient
}

func newOAuth2(clientID oauth2ClientID, clientSecret oauth2ClientSecret, callbackURI URI) *oauth2Client {
	return &oauth2Client{
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURI:  callbackURI,

		httpClient: http.DefaultClient,
	}
}

func (x *oauth2Client) authURI(authURI URI, scopes []string) URI {
	q := &url.Values{}
	q.Add("client_id", string(x.clientID))
	q.Add("redirect_uri", string(x.callbackURI))
	q.Add("response_type", "code")
	q.Add("scope", strings.Join(scopes, " "))

	return authURI + URI("?"+q.Encode())
}

func (x *oauth2Client) getToken(ctx context.Context, uri URI, code oauth2Code) (*oauth2AccessToken, error) {
	body := &url.Values{}
	body.Add("grant_type", "authorization_code")
	body.Add("code", string(code))
	body.Add("client_id", string(x.clientID))
	body.Add("client_secret", string(x.clientSecret))
	body.Add("redirect_uri", string(x.callbackURI))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, string(uri), bytes.NewReader([]byte(body.Encode())))
	if err != nil {
		return nil, goerr.Wrap(err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := x.httpClient.Do(req)
	if err != nil {
		return nil, goerr.Wrap(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, goerr.Wrap(ErrInvalidGoogleOAuth2Proc, "can not read token").With("body", string(body)).With("status", resp.StatusCode)
	}

	var token oauth2AccessToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, goerr.Wrap(err)
	}

	return &token, nil
}

func (x *oauth2Client) getUserInfo(ctx context.Context, uri URI, accessToken accessToken, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, string(uri), nil)
	if err != nil {
		return goerr.Wrap(err)
	}
	req.Header.Add("Authorization", "Bearer "+string(accessToken))
	resp, err := x.httpClient.Do(req)
	if err != nil {
		return goerr.Wrap(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return goerr.Wrap(ErrInvalidGoogleOAuth2Proc, "can not read user info").With("body", string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return goerr.Wrap(err)
	}

	return nil
}
