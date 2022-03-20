package omniauth

import "net/http"

type Policy func(r *http.Request, u *User) bool
type Policies []Policy

func (x Policies) denied(r *http.Request, u *User) bool {
	// If no policy, default is all access permitted
	if len(x) == 0 {
		return false
	}

	for _, policy := range x {
		if policy(r, u) {
			return false
		}
	}

	return true
}

func WithPolicy(policies ...Policy) Option {
	return func(n *OmniAuth) error {
		n.policies = append(n.policies, policies...)
		return nil
	}
}

func AllowedEmailsPolicy(emailAddrs []string) Policy {
	return func(r *http.Request, u *User) bool {
		if u.Email.IsEmpty() {
			return false
		}
		for i := range emailAddrs {
			if emailAddrs[i] == string(u.Email) {
				return true
			}
		}
		return false
	}
}
