package microbo

import (
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"github.com/joho/godotenv"
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

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Headers", "Accept-Language, Content-Language, Content-Type, Origin")
		if r.Method == http.MethodOptions {
			w.WriteHeader(200)
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

func init() {
	godotenv.Load()
}

type Server struct {
	http.Server
	Router   *mux.Router
	DB       *gorm.DB
	RootPath string
}

func (server *Server) setupStatic(path string) {
	if server.RootPath != "" {
		fs := httpNoDirFileSystem{http.Dir(server.RootPath)}
		staticFileHandler := http.FileServer(fs)
		server.Router.
			PathPrefix(path).
			Handler(http.StripPrefix(path, staticFileHandler))
	}
}

func (server *Server) HandleFunc(method, path string, f func(http.ResponseWriter, *http.Request)) {
	server.Router.HandleFunc(path, f).Methods(method, "OPTIONS")
}

func (server *Server) Run() {
	log.Printf("Server started on %s\n", server.Addr)
	log.Fatal(server.ListenAndServeTLS(os.Getenv("CERT_FILE"), os.Getenv("CERT_KEY")))
}

func NewServer() *Server {
	var db *gorm.DB
	var err error
	if os.Getenv("DB_DIALECT") != "" {
		db, err = gorm.Open(os.Getenv("DB_DIALECT"), os.Getenv("DB_CONNECTION"))
		if err != nil {
			log.Panic(err)
		}
	}
	router := mux.NewRouter()
	router.Use(corsMiddleware)
	router.Use(logMiddleware)
	server := &Server{
		Server: http.Server{
			Handler:      router,
			Addr:         os.Getenv("SERVER_ADDR"),
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		},
		Router:   router,
		DB:       db,
		RootPath: os.Getenv("ROOT_PATH"),
	}
	server.setupStatic(os.Getenv("ROOT_PATH_ENDPOINT"))
	return server
}
