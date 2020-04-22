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
DB_DIALECT="sqlite"
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
  "net/http"

  _ "github.com/jinzhu/gorm/dialects/mysql"
  "github.com/pioz/microbo"
)

type MyServer struct {
  *microbo.Server
  Data string
}

func NewServer(data string) *MyServer {
  server := &MyServer{
    Server: microbo.NewServer(nil),
    Data:   data,
  }
  server.HandleFunc("GET", "/ping", server.pingHandler)
  return server
}

func (server *MyServer) pingHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "application/json")
  encoder := json.NewEncoder(w)
  encoder.Encode(server.Data)
}

func main() {
  server := NewServer("pong")
  server.Run()
}

```

And yeah, your microservice is ready!

You can use your database with `server.DB` that is a `*gorm.DB` pointer. You can find all info about ["The fantastic ORM library for Golang" here](https://gorm.io/).

You can use the router with `server.Router` that is a `*mux.Router` pointer. You can find all info about ["Gorilla web toolkit" here](https://github.com/gorilla/mux).

## Questions or problems?

If you have any issues please add an [issue on
GitHub](https://github.com/pioz/microbo/issues) or fork the project and send a
pull request.

## Copyright

Copyright (c) 2020 [Enrico Pilotto (@pioz)](https://github.com/pioz). See
[LICENSE](https://github.com/pioz/microbo/blob/master/LICENSE) for details.
