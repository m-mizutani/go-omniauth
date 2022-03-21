# go-omniauth

`go-omniauth` is a middleware of multi-provider authentication for web applications in Go. It's inspired by [omnioauth](https://github.com/omniauth/omniauth) in Ruby on Rails. `go-omniauth` provides HTTP middleware as `func(http.Handler) http.Handler` and it's compatible with major web application frameworks in Go.

- [chi](https://github.com/go-chi/chi)
- [echo](https://github.com/labstack/echo)
- [gorilla/mux](https://github.com/gorilla/mux)

For example, sample code integrating with `chi` is following.

```go
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi"

	omniauth "github.com/m-mizutani/go-omniauth"
)

func main() {
	r := chi.NewRouter()

	r.Use(omniauth.New(
		omniauth.WithGoogleOAuth2(
			os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
			os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
			os.Getenv("GOOGLE_OAUTH_CLIENT_CALLBACK_URI"),
		),
		omniauth.WithPolicy(omniauth.AllowedAll()),
	))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(omniauth.CtxUserKey).(*omniauth.User)
		if !ok {
			panic("no user data")
		}

		body := fmt.Sprintf(`<html><body><h1>Hello, %s</h1></body></html>`, user.Name)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	})

	fmt.Println("starting http://127.0.0.1:3333")
	http.ListenAndServe("127.0.0.1:3333", r)
}
```

See more example codes in [./examples](./examples/).
