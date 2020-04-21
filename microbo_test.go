package microbo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/stretchr/testify/assert"
)

func setEnvVars() {
	os.Setenv("CERT_FILE", "./cert/localhost+1.pem")
	os.Setenv("CERT_KEY", "./cert/localhost+1-key.pem")
	os.Setenv("DB_CONNECTION", ":memory:")
	os.Setenv("DB_DIALECT", "sqlite3")
	os.Setenv("ROOT_PATH", "./public")
	os.Setenv("ROOT_PATH_ENDPOINT", "/public/")
	os.Setenv("SERVER_ADDR", "127.0.0.1:3000")
}

func handleHello(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.Encode("world")
}

func TestHelloWorld(t *testing.T) {
	setEnvVars()
	server := NewServer()
	server.HandleFunc("GET", "/hello", handleHello)
	recorder := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/hello", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.HeaderMap["Content-Type"][0])

	var r string
	json.Unmarshal(recorder.Body.Bytes(), &r)

	assert.Equal(t, "world", r)
}
