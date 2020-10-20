# Microbo

Microbo is a micro framework to create micro API webservers in go. A webserver
that use Microbo require a very minimal configuration (just create a `.env` file) and support a DB
connection, CORS, authentication with JWT and HTTP2 out of the box.

## Usage

First of all you have to create `.env` file like this:

```
CERT_FILE="./cert/localhost+1.pem"
CERT_KEY="./cert/localhost+1-key.pem"
DB_CONNECTION=":memory:"
JWT_KEY="1234"
ROOT_PATH="/var/www/public"
ROOT_PATH_ENDPOINT="/public/"
SERVER_ADDR="127.0.0.1:3000"
```

You can generate the certificate using [mkcert](https://github.com/FiloSottile/mkcert).

Then create your `main.go` file

```go
package main

import (
  "encoding/json"
  "fmt"
  "net/http"
  "os"

  "github.com/pioz/microbo"
  "gorm.io/driver/sqlite"
  "gorm.io/gorm"
)

type Server struct {
  *microbo.Server
}

func NewServer(db *gorm.DB) *Server {
  server := &Server{Server: microbo.NewServer(db)}
  server.HandleFunc("GET", "/ping", pingHandler)
  server.HandleFuncWithAuth("GET", "/secure-ping", server.securePingHandler)
  return server
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "application/json")
  encoder := json.NewEncoder(w)
  encoder.Encode("pong")
}

func (server *Server) securePingHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "application/json")
  userId := r.Context().Value("user_id").(uint)
  user := microbo.DefaultUser{} // or your user model struct
  server.DB.Where("id = ?", userId).Find(&user)
  encoder := json.NewEncoder(w)
  encoder.Encode(fmt.Sprintf("pong %s", user.Email))
}

func main() {
  os.Setenv("SERVER_ADDR", "127.0.0.1:3001") // override env variable
  db, _ := gorm.Open(sqlite.Open(os.Getenv("DB_CONNECTION")), nil)
  NewServer(db).Run()
}
```

And yeah, your microservice is ready!

You can use your database with `server.DB` that is a `*gorm.DB` pointer. You can find all info about ["The fantastic ORM library for Golang" here](https://gorm.io/).

You can use the router with `server.Router` that is a `*mux.Router` pointer. You can find all info about ["Gorilla web toolkit" here](https://github.com/gorilla/mux).

Also the following authentication endpoints are available:

- POST `/auth/register`
- POST `/auth/login`
- POST `/auth/refresh`

Here the [godoc](https://godoc.org/github.com/pioz/microbo) to know all about microbo.

## Questions or problems?

If you have any issues please add an [issue on
GitHub](https://github.com/pioz/microbo/issues) or fork the project and send a
pull request.

## Copyright

Copyright (c) 2020 [Enrico Pilotto (@pioz)](https://github.com/pioz). See
[LICENSE](https://github.com/pioz/microbo/blob/master/LICENSE) for details.
