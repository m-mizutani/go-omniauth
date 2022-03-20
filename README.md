# Naberius

`naberius` is a middleware of multi-provider authentication for web applications in Go. It's inspired by [omnioauth](https://github.com/omniauth/omniauth).

![Naberius](https://user-images.githubusercontent.com/605953/159140834-b9937306-64a6-4c67-8e91-3abffba05e86.png)

`naberius` provides HTTP middleware as `func(http.Handler) http.Handler` and it's compatible with major web application frameworks in Go.

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
	"github.com/m-mizutani/naberius"
)

func main() {
	r := chi.NewRouter()
	r.Use(naberius.New(
		naberius.WithGoogleOAuth2(
			os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
			os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
			os.Getenv("GOOGLE_OAUTH_CLIENT_CALLBACK_URI"),
		),
	))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context().Value("naberius").(*naberius.Context)

		body := fmt.Sprintf(`<html><body><h1>Hello, %s</h1></body></html>`, ctx.User().Name)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	})

	http.ListenAndServe(":3333", r)
}
```

See more example codes in [./examples](./examples/).
