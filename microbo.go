// Microbo is a micro framework to create micro API webservers in go. A
// webserver that use Microbo require a very minimal configuration (just
// create a .env file) and support a DB connection, CORS, authentication with
// JWT and HTTP2 out of the box.
package microbo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/copier"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}
}

type httpNoDirFileSystem struct {
	fs http.FileSystem
}

func (fs httpNoDirFileSystem) Open(path string) (http.File, error) {
	file, err := fs.fs.Open(path)
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if stat.IsDir() {
		return nil, os.ErrNotExist
	}
	return file, nil
}

type jwtClaims struct {
	UserId uint
	jwt.StandardClaims
}

// User Database Model

// This is the interface that you have to implement to use a custom user
// model.
type UserModel interface {
	GetID() uint
	GetEmail() string
	GetPassword() string
	TableName() string
	EmailColumnName() string
}

// The default user struct used to manage users. However, you can always use
// your own user model (see below).
type DefaultUser struct {
	ID       uint   `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"`
}

// Return the ID of user record as uint.
func (u DefaultUser) GetID() uint {
	return u.ID
}

// Return the email of user record as string.
func (u DefaultUser) GetEmail() string {
	return u.Email
}

// Return the encrypted password of user record as string.
func (u DefaultUser) GetPassword() string {
	return u.Password
}

// Return the user table name in your DB. Default "users".
func (DefaultUser) TableName() string {
	return "users"
}

// Return the user email column name in your DB. Default "email".
func (DefaultUser) EmailColumnName() string {
	return "email"
}

type Conf struct {
	// Pointer to gorm ORM database.
	// See https://pkg.go.dev/gorm.io/gorm#DB
	DB *gorm.DB
	// Set a custom user model. The custom user model must implement the interface UserModel. Here and example:
	//  type FullUser struct {
	//   	UID         uint `gorm:"auto_increment;primary_key"`
	//   	Mail        string
	//   	EncPassword string
	//   	Username    string
	//   	Role        bool
	//  }
	//
	//  func (u FullUser) GetID() uint {
	//  	return u.UID
	//  }
	//
	//  func (u FullUser) GetEmail() string {
	//  	return u.Mail
	//  }
	//
	//  func (u FullUser) GetPassword() string {
	//  	return u.EncPassword
	//  }
	//
	//  func (FullUser) TableName() string {
	//  	return "user"
	//  }
	//
	//  func (FullUser) EmailColumnName() string {
	//  	return "mail"
	//  }
	//
	//  func (user *FullUser) ID(id uint) {
	//  	user.UID = id
	//  }
	//
	//  // Used for copier (see https://github.com/jinzhu/copier)
	//  func (user *FullUser) Email(email string) {
	//  	user.Mail = email
	//  }
	//
	//  // Used for copier (see https://github.com/jinzhu/copier)
	//  func (user *FullUser) Password(password string) {
	//  	user.EncPassword = password
	//  }
	//
	//  func (u FullUser) MarshalJSON() ([]byte, error) {
	//  	return json.Marshal(struct {
	//  		ID        uint   `json:"id"`
	//  		Mail      string `json:"mail"`
	//  		Username  string `json:"username"`
	//  		RandToken string `json:"rand_token"`
	//  	}{
	//  		ID:        u.UID,
	//  		Mail:      u.Mail,
	//  		Username:  u.Username,
	//  		RandToken: "RAND TOKEN",
	//  	})
	//  }
	//
	//  conf := microbo.Conf{UserModel: &FullUser{}}
	//  server := microbo.NewServerWithOpts(&conf)
	//  server.Run()
	// The /auth/login endpoint will return the user json defined by
	// FullUser#MarshalJSON.
	UserModel UserModel
	// The Log middleware
	// See https://godoc.org/github.com/gorilla/mux#Router.Use
	LogMiddleware mux.MiddlewareFunc
	// The Timeout middleware. The default use http.TimeoutHandler with dt
	// parameters set to 2 seconds.
	// See https://godoc.org/net/http#TimeoutHandler
	// See https://godoc.org/github.com/gorilla/mux#Router.Use
	// An example to change the timeout:
	//  conf := microbo.Conf{
	//  	TimeoutMiddleware: func(next http.Handler) http.Handler {
	//  		return http.TimeoutHandler(next, 60*time.Second, "Timeout")
	//  	},
	//  }
	TimeoutMiddleware mux.MiddlewareFunc
	// ReadTimeout is the maximum duration for reading the entire request,
	// including the body.
	// See https://godoc.org/net/http#Server
	ReadTimeout *time.Duration
	// WriteTimeout is the maximum duration before timing out writes of the
	// response.
	// See https://godoc.org/net/http#Server
	WriteTimeout *time.Duration
}

// The base server struct. It contains the Router and the DB access.
type Server struct {
	// http.Server variable. See https://godoc.org/net/http#Server
	http.Server
	// Router registers routes to be matched and dispatches a handler. See
	// https://godoc.org/github.com/gorilla/mux#Router
	Router *mux.Router
	// Pointer to gorm ORM database. See
	// https://pkg.go.dev/gorm.io/gorm#DB
	DB *gorm.DB
	// The path of the public folder. Files inside will be serverd as static
	// files.
	RootPath string

	pathsWithAuthRouter *mux.Router
	jwtKey              string
	userModel           UserModel
}

// Create a new Microbo server.
//
// Microbo uses config enviroment variables that can be store in a handy .env
// file. The available env variables are:
//  - CERT_FILE: path to the certificate file (.pem). For dev purpose you can use mkcert (https://github.com/FiloSottile/mkcert).
//  - CERT_KEY: path to the certificate key file (.pem).
//  - DB_CONNECTION: a Gorm database connection string (es: "root@tcp(127.0.0.1:3306)/testdb?charset=utf8mb4&parseTime=True").
//  - ROOT_PATH: path of the public root path. Files inside will be served as static files.
//  - ROOT_PATH_ENDPOINT: URL path to access public files (es: /public/).
//  - SERVER_ADDR: the server address with port (es: 127.0.0.1:3000).
//  - JWT_KEY: the JWT key used to sign tokens.
func NewServer(db *gorm.DB) *Server {
	return NewServerWithOpts(&Conf{DB: db})
}

// Create a new Microbo server with configuration options.
func NewServerWithOpts(conf *Conf) *Server {
	if conf == nil {
		conf = &Conf{}
	}
	if conf.UserModel == nil {
		conf.UserModel = &DefaultUser{}
	}
	if conf.LogMiddleware == nil {
		conf.LogMiddleware = logMiddleware
	}
	if conf.TimeoutMiddleware == nil {
		conf.TimeoutMiddleware = timeoutMiddleware
	}
	if conf.ReadTimeout == nil {
		readTimeout := 15 * time.Second
		conf.ReadTimeout = &readTimeout
	}
	if conf.WriteTimeout == nil {
		writeTimeout := 15 * time.Second
		conf.WriteTimeout = &writeTimeout
	}

	router := mux.NewRouter()
	server := &Server{
		Server: http.Server{
			Handler:      router,
			Addr:         os.Getenv("SERVER_ADDR"),
			ReadTimeout:  *conf.ReadTimeout,
			WriteTimeout: *conf.WriteTimeout,
		},
		Router:   router,
		DB:       conf.DB,
		RootPath: os.Getenv("ROOT_PATH"),

		pathsWithAuthRouter: mux.NewRouter(),
		jwtKey:              os.Getenv("JWT_KEY"),
		userModel:           conf.UserModel,
	}

	server.Router.Use(corsMiddleware)
	server.Router.Use(conf.LogMiddleware)
	server.Router.Use(conf.TimeoutMiddleware)
	server.setupStatic(os.Getenv("ROOT_PATH_ENDPOINT"))
	server.addJWTAuthSupport()
	return server
}

// Public API

// HandleFunc registers the handler function for the given pattern in the mux
// Router. The documentation for ServeMux explains how patterns are matched.
// See https://godoc.org/net/http#HandleFunc
func (server *Server) HandleFunc(method, path string, f func(http.ResponseWriter, *http.Request)) {
	server.Router.HandleFunc(path, f).Methods(method, http.MethodOptions)
}

// Handles registered with HandleFuncWithAuth must be requested with a valid
// JWT bearer token. Inside the handler you can retrieve the authenticated
// userId with
//   userId := r.Context().Value("user_id").(uint)
//
// Built in authentication endpoints are:
//   // Register a new user
//   curl --location --request POST 'https://localhost:3000/auth/register' \
//   --header 'Content-Type: application/json' \
//   --data-raw '{
//     "email": "epilotto@gmx.com",
//     "password": "qwerty"
//   }'
// Return 200 if user has successfully registered, or other http error codes
// if not. No body will be returned in the response.
//
//   // Get a new JWT token
//   curl --location --request POST 'https://localhost:3000/auth/login' \
//   --header 'Content-Type: application/json' \
//   --data-raw '{
//     "email": "epilotto@gmx.com",
//     "password": "qwerty"
//   }'
// Return 200 and the json with user data if user has successfully
// autheticated. The token will be present in the header under the X-Token
// key.
//
//   // Refresh a JWT token
//   curl --location --request POST 'https://localhost:3000/auth/refresh' \
//   --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VySWQiOjExLCJleHAiOjE1ODc2NzIzOTl9.vEoYBueacCA_JQkPmDCwpfIutsC5jQmYfL692q0Nrrk' \
//   --header 'Content-Type: application/json'
// Return 200 if the token has successfully refreshed. The new token will be
// present in the header under the X-Token key. No body will be returned in
// the response.
//
// Also, these endpoints and the authentication with JWT token are enabled
// only if exists the env variable JWT_KEY and a database table named "users"
// with the columns "id", "email" and "password". Password will be stored as a
// bcrypt hash.
func (server *Server) HandleFuncWithAuth(method, path string, f func(http.ResponseWriter, *http.Request)) {
	server.pathsWithAuthRouter.NewRoute().Path(path)
	server.HandleFunc(method, path, f)
}

// Run the server.
func (server *Server) Run() {
	log.Printf("Server started on %s\n", server.Addr)
	log.Fatal(server.ListenAndServeTLS(os.Getenv("CERT_FILE"), os.Getenv("CERT_KEY")))
}

// Shutdown the server.
func (server *Server) Shutdown() {
	log.Println("Server is shutting down")
}

// Setup Methods

func (server *Server) setupStatic(path string) {
	if server.RootPath != "" {
		fs := httpNoDirFileSystem{http.Dir(server.RootPath)}
		staticFileHandler := http.FileServer(fs)
		server.Router.
			PathPrefix(path).
			Handler(http.StripPrefix(path, staticFileHandler))
	}
}

func (server *Server) setupAuthHandlers() {
	server.HandleFunc("POST", "/auth/register", server.registerHandler)
	server.HandleFunc("POST", "/auth/login", server.loginHandler)
	server.HandleFuncWithAuth("POST", "/auth/refresh", server.refreshHandler)
}

// Middlewares

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessControlAllowOrigin := r.Header.Get("Origin")
		w.Header().Add("Access-Control-Allow-Origin", accessControlAllowOrigin)
		w.Header().Add("Access-Control-Expose-Headers", "X-Token")
		if r.Method == http.MethodOptions {
			accessControlAllowMethods := r.Header.Get("Access-Control-Request-Method")
			accessControlAllowHeaders := r.Header.Get("Access-Control-Request-Headers")
			w.Header().Add("Access-Control-Allow-Methods", accessControlAllowMethods)
			w.Header().Add("Access-Control-Allow-Headers", accessControlAllowHeaders)
			w.Header().Add("Vary", "Origin") // This tell to browser to send the Origin header also in the real request
			// w.Header().Add("Vary", "Access-Control-Request-Method")
			// w.Header().Add("Vary", "Access-Control-Request-Headers")
			w.Header().Add("Access-Control-Max-Age", "86400") // Do not request preflight for the next 24 hours
			w.WriteHeader(http.StatusOK)
			return
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Println(err)
		}
		log.Printf("%s -> %s %s\n%s\n\n", r.RemoteAddr, r.Method, r.URL, requestDump)
		next.ServeHTTP(w, r)
	})
}

func timeoutMiddleware(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, 2*time.Second, "Timeout")
}

func (server *Server) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var match mux.RouteMatch
		if !server.pathsWithAuthRouter.Match(r, &match) {
			next.ServeHTTP(w, r)
			return
		}
		tokenHeader := r.Header.Get("Authorization")
		splittedToken := strings.Split(tokenHeader, " ")
		if len(splittedToken) != 2 {
			http.Error(w, "Invalid JWT token header", http.StatusForbidden)
			return
		}
		tokenString := splittedToken[1]
		claims := &jwtClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(server.jwtKey), nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if !token.Valid {
			http.Error(w, "JWT token is not valid", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), "user_id", claims.UserId)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Handlers

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (server *Server) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	var request registerRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil || request.Email == "" || request.Password == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	user := server.copyUserModel()
	err = server.DB.Table(user.TableName()).Where(fmt.Sprintf("%s = ?", user.EmailColumnName()), request.Email).First(user).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		http.Error(w, "Email already in use", http.StatusConflict)
		return
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	defaultUser := DefaultUser{Email: request.Email, Password: string(hashedPassword)}

	if err = copier.Copy(user, defaultUser); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err = server.DB.Create(user).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (server *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	var request loginRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil || request.Email == "" || request.Password == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	user := server.copyUserModel()
	err = server.DB.Where(fmt.Sprintf("%s = ?", user.EmailColumnName()), request.Email).First(user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		http.Error(w, "Invalid email and/or password", http.StatusUnauthorized)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.GetPassword()), []byte(request.Password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		http.Error(w, "Invalid email and/or password", http.StatusUnauthorized)
		return
	}
	claims := &jwtClaims{UserId: user.GetID()}

	w.Header().Add("Content-Type", "application/json")
	server.addTokenToHeader(claims, w)
	encoder := json.NewEncoder(w)
	if err = encoder.Encode(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (server *Server) refreshHandler(w http.ResponseWriter, r *http.Request) {
	userId := r.Context().Value("user_id").(uint)
	claims := &jwtClaims{UserId: userId}
	w.Header().Add("Content-Type", "application/json")
	server.addTokenToHeader(claims, w)
	w.WriteHeader(http.StatusOK)
}

// Private functions

func (server *Server) copyUserModel() UserModel {
	return reflect.New(reflect.ValueOf(server.userModel).Elem().Type()).Interface().(UserModel)
}

func (server *Server) addTokenToHeader(claims *jwtClaims, w http.ResponseWriter) {
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = time.Now().Add(time.Hour * 24 * 30).Unix() // token duration is 1 month
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	tokenString, err := token.SignedString([]byte(server.jwtKey))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Add("X-Token", tokenString)
}

func (server *Server) addJWTAuthSupport() {
	if server.DB != nil && os.Getenv("JWT_KEY") != "" && server.DB.Migrator().HasTable(server.userModel) && server.DB.Migrator().HasColumn(server.userModel, server.userModel.EmailColumnName()) {
		server.Router.Use(server.jwtMiddleware)
		server.setupAuthHandlers()
	}
}
