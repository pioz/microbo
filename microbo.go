// Microbo is a micro framework to create micro API webservers in go. A
// webserver that use Microbo require a very minimal configuration (just
// create a `.env` file) and support a DB connection, CORS, authentication
// with JWT and HTTP2 out of the box.
package microbo

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type httpNoDirFileSystem struct {
	fs http.FileSystem
}

func (fs httpNoDirFileSystem) Open(path string) (http.File, error) {
	file, err := fs.fs.Open(path)
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if stat.IsDir() {
		return nil, os.ErrNotExist
	}
	return file, nil
}

type jwtClaims struct {
	UserId uint
	jwt.StandardClaims
}

func init() {
	godotenv.Load()
}

// The base server struct. It contains the Router and the DB access.
type Server struct {
	// http.Server variable. See https://godoc.org/net/http#Server
	http.Server
	// Router registers routes to be matched and dispatches a handler. See
	// https://godoc.org/github.com/gorilla/mux#Router
	Router *mux.Router
	// Pointer to gorm ORM database. See
	// https://godoc.org/github.com/jinzhu/gorm#DB
	DB *gorm.DB
	// The path of the public folder. Files inside will be serverd as static
	// files.
	RootPath            string
	pathsWithAuthRouter *mux.Router
	jwtKey              string
}

// Create a new Microbo server. You can pass a pointer to an existing gorm.DB
// variable, or nil to create a new one using `.env` variables `DB_DIALECT`
// and `DB_CONNECTION`. To create a new server Microbo use config enviroment
// variables that can be store in a handy `.env` file. The available env
// variables are:
//   * CERT_FILE: path to the certificate file (.pem). For dev purpose you can use mkcert (https://github.com/FiloSottile/mkcert).
//   * CERT_KEY: path to the certificate key file (.pem).
//   * DB_CONNECTION: a Gorm database connection string (es: "root@tcp(127.0.0.1:3306)/testdb?charset=utf8mb4&parseTime=True").
//   * DB_DIALECT: one of the SQL dialects made available by Gorm.
//   * ROOT_PATH: path of the public root path. Files inside will be served as static files.
//   * ROOT_PATH_ENDPOINT: URL path to access public files (es: /public/).
//   * SERVER_ADDR: the server address with port (es: 127.0.0.1:3000).
//   * JWT_KEY: the JWT key used to sign tokens.
func NewServer(db *gorm.DB) *Server {
	if db == nil {
		var err error
		if os.Getenv("DB_DIALECT") != "" {
			db, err = gorm.Open(os.Getenv("DB_DIALECT"), os.Getenv("DB_CONNECTION"))
			if err != nil {
				log.Panic(err)
			}
		}
	}
	router := mux.NewRouter()
	server := &Server{
		Server: http.Server{
			Handler:      router,
			Addr:         os.Getenv("SERVER_ADDR"),
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		},
		Router:              router,
		DB:                  db,
		RootPath:            os.Getenv("ROOT_PATH"),
		pathsWithAuthRouter: mux.NewRouter(),
		jwtKey:              os.Getenv("JWT_KEY"),
	}
	// server.Router.Use(mux.CORSMethodMiddleware(server.Router))
	server.Router.Use(corsMiddleware)
	server.Router.Use(logMiddleware)
	server.setupStatic(os.Getenv("ROOT_PATH_ENDPOINT"))
	if server.existValidUserTable() {
		server.Router.Use(server.jwtMiddleware)
		server.setupAuthHandlers()
	}
	return server
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
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Headers", "Accept-Language, Authorization, Content-Language, Content-Type, Origin")
		w.Header().Add("Access-Control-Expose-Headers", "X-Token")
		if r.Method == http.MethodOptions {
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

// Public API

// HandleFunc registers the handler function for the given pattern in the mux
// Router. The documentation for ServeMux explains how patterns are matched.
// See https://godoc.org/net/http#HandleFunc
func (server *Server) HandleFunc(method, path string, f func(http.ResponseWriter, *http.Request)) {
	// server.Router.HandleFunc(path, f).Methods(method, http.MethodOptions)
	server.Router.HandleFunc(path, f).Methods(method, http.MethodOptions)
}

// Handles registered with HandleFuncWithAuth must be requested with a valid
// JWT bearer token. Inside the handler you can retrieve the authenticated
// `userId` with
//   userId := r.Context().Value("user_id").(uint)
// Built in authentication endpoints are:
//   // Register a new user
//   curl --location --request POST 'https://localhost:3000/auth/register' \
//   --header 'Content-Type: application/json' \
//   --data-raw '{
//     "email": "epilotto@gmx.com",
//     "password": "qwerty"
//   }'
//
//   // Get a new JWT token
//   curl --location --request POST 'https://localhost:3000/auth/login' \
//   --header 'Content-Type: application/json' \
//   --data-raw '{
//     "email": "epilotto@gmx.com",
//     "password": "qwerty"
//   }'
//
//   // Refresh a JWT token
//   curl --location --request POST 'https://localhost:3000/auth/refresh' \
//   --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VySWQiOjExLCJleHAiOjE1ODc2NzIzOTl9.vEoYBueacCA_JQkPmDCwpfIutsC5jQmYfL692q0Nrrk' \
//   --header 'Content-Type: application/json'
// In the responses of these endpoints, the token will be present in the
// header under the X-Token key. Also, these endpoints and the authentication
// by JWT token are enabled only if exists a database table named `users` with
// the columns `id`, `email` and `password`. Password will be stored as a
// bcrypt hash.
func (server *Server) HandleFuncWithAuth(method, path string, f func(http.ResponseWriter, *http.Request)) {
	server.pathsWithAuthRouter.NewRoute().Path(path)
	server.HandleFunc(method, path, f)
}

// Run the server
func (server *Server) Run() {
	log.Printf("Server started on %s\n", server.Addr)
	log.Fatal(server.ListenAndServeTLS(os.Getenv("CERT_FILE"), os.Getenv("CERT_KEY")))
}

// Shutdown the server
func (server *Server) Shutdown() {
	log.Println("Server is shutting down")
	server.DB.Close()
}

// Handlers

type userModel struct {
	gorm.Model
	Email    string
	Password string
}

func (userModel) TableName() string {
	return "users"
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authResponse struct {
	Token string `json:"token"`
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
	if !server.DB.Table("users").Where("email = ?", request.Email).Find(&userModel{}).RecordNotFound() {
		http.Error(w, "Email already in use", http.StatusConflict)
		return
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	user := userModel{Email: request.Email, Password: string(hashedPassword)}
	if err = server.DB.Create(&user).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	claims := &jwtClaims{UserId: user.ID}
	server.respondWithToken(claims, w)
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
	user := userModel{}
	if server.DB.Where("email = ?", request.Email).Find(&user).RecordNotFound() {
		http.Error(w, "Invalid email and/or password", http.StatusUnauthorized)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		http.Error(w, "Invalid email and/or password", http.StatusUnauthorized)
		return
	}
	claims := &jwtClaims{UserId: user.ID}
	server.respondWithToken(claims, w)
}

func (server *Server) refreshHandler(w http.ResponseWriter, r *http.Request) {
	userId := r.Context().Value("user_id").(uint)
	claims := &jwtClaims{UserId: userId}
	server.respondWithToken(claims, w)
}

// Private functions

func (server *Server) respondWithToken(claims *jwtClaims, w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = time.Now().Add(time.Hour * 24 * 30).Unix() // token duration is 1 month
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	tokenString, err := token.SignedString([]byte(server.jwtKey))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println(tokenString)
	w.Header().Add("X-Token", tokenString)
	w.WriteHeader(http.StatusOK)
}

func (server *Server) existValidUserTable() bool {
	return server.DB.Dialect().HasColumn("users", "id") && server.DB.Dialect().HasColumn("users", "email") && server.DB.Dialect().HasColumn("users", "password")
}
