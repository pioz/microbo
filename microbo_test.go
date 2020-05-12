package microbo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func setEnvVars() {
	os.Setenv("CERT_FILE", "./cert/localhost+1.pem")
	os.Setenv("CERT_KEY", "./cert/localhost+1-key.pem")
	os.Setenv("DB_CONNECTION", ":memory:")
	os.Setenv("DB_DIALECT", "sqlite3")
	os.Setenv("ROOT_PATH", "./fixtures/public")
	os.Setenv("ROOT_PATH_ENDPOINT", "/public/")
	os.Setenv("SERVER_ADDR", "127.0.0.1:3000")
}

func populateDB() *gorm.DB {
	db, _ := gorm.Open(os.Getenv("DB_DIALECT"), os.Getenv("DB_CONNECTION"))
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("querty"), bcrypt.DefaultCost)
	user := DefaultUser{Email: "pioz@sample.com", Password: string(hashedPassword)}
	db.AutoMigrate(&user)
	db.Create(&user)
	return db
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.Encode("pong")
}

func TestGetRequestHandler(t *testing.T) {
	setEnvVars()
	server := NewServer()
	server.HandleFunc("GET", "/ping", handlePing)
	recorder := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/ping", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.HeaderMap["Content-Type"][0])

	var r string
	json.Unmarshal(recorder.Body.Bytes(), &r)

	assert.Equal(t, "pong", r)
}

type CustomServer struct {
	*Server
	Data string
}

func NewCustomServer(data string) *CustomServer {
	return &CustomServer{
		Server: NewServer(),
		Data:   data,
	}
}

func (server *CustomServer) handlePingCustomServer(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.Encode(server.Data)
}

func TestHelloWorldWithCustomServer(t *testing.T) {
	setEnvVars()
	server := NewCustomServer("pong")
	server.HandleFunc("GET", "/ping", server.handlePingCustomServer)
	recorder := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/ping", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.HeaderMap["Content-Type"][0])

	var r string
	json.Unmarshal(recorder.Body.Bytes(), &r)

	assert.Equal(t, "pong", r)
}

func TestGetStaticFile(t *testing.T) {
	setEnvVars()
	server := NewServer()
	recorder := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/public/images/eld_197.png", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "image/png", recorder.HeaderMap["Content-Type"][0])
}

func Test404StaticFile(t *testing.T) {
	setEnvVars()
	server := NewServer()
	recorder := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/public/images/not_exists.png", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestRegistrationNoBody(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	req, _ := http.NewRequest("POST", "/auth/register", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestRegistrationInvalidParams(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	payload := []byte(`{"emailz":"pioz@sample.com","passwordz":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestRegistrationEmailAlreadyExist(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	payload := []byte(`{"email":"pioz@sample.com","password":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusConflict, recorder.Code)
}

func TestRegistration(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	payload := []byte(`{"email":"hanfry@sample.com","password":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Nil(t, recorder.HeaderMap["X-Token"])

	user := DefaultUser{}
	server.DB.Last(&user)
	assert.Equal(t, "hanfry@sample.com", user.Email)
	assert.NotEmpty(t, user.Password)
}

func TestLoginNoBody(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	req, _ := http.NewRequest("POST", "/auth/login", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestLoginInvalidParams(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	payload := []byte(`{"emailz":"pioz@sample.com","passwordz":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestLoginInvalidEmail(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	payload := []byte(`{"email":"john@sample.com","password":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestLoginInvalidPassword(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	payload := []byte(`{"email":"pioz@sample.com","password":"quertyz"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestLogin(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	payload := []byte(`{"email":"pioz@sample.com","password":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.HeaderMap["Content-Type"][0])
	assert.NotEmpty(t, recorder.HeaderMap["X-Token"][0])

	user := DefaultUser{}
	json.Unmarshal(recorder.Body.Bytes(), &user)
	assert.Equal(t, user.Email, "pioz@sample.com")
	assert.NotEmpty(t, user.ID)
}

func TestRefreshTokenWithoutToken(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	req, _ := http.NewRequest("POST", "/auth/refresh", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestRefreshToken(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	recorder := httptest.NewRecorder()
	populateDB()

	payload := []byte(`{"email":"pioz@sample.com","password":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	token := recorder.HeaderMap["X-Token"][0]

	time.Sleep(time.Second)

	recorder = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/auth/refresh", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.HeaderMap["Content-Type"][0])
	assert.NotEqual(t, token, recorder.HeaderMap["X-Token"][0])
}

func TestNoAuthIfNoValidUserTable(t *testing.T) {
	setEnvVars()
	server := NewServer()
	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/auth/login", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func authPingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	userId := r.Context().Value("user_id").(uint)
	encoder := json.NewEncoder(w)
	encoder.Encode(fmt.Sprintf("pong %d", userId))
}

func TestGetRequestHandlerWithAuth(t *testing.T) {
	setEnvVars()
	server := NewServerWithOpts(&Conf{DB: populateDB()})
	server.HandleFuncWithAuth("GET", "/ping", authPingHandler)

	user := DefaultUser{}
	server.DB.Where("email = ?", "pioz@sample.com").Find(&user)

	recorder := httptest.NewRecorder()
	payload := []byte(`{"email":"pioz@sample.com","password":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	token := recorder.HeaderMap["X-Token"][0]
	fmt.Println(token)

	recorder = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/ping", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.HeaderMap["Content-Type"][0])

	var r string
	json.Unmarshal(recorder.Body.Bytes(), &r)
	assert.Equal(t, fmt.Sprintf("pong %d", user.ID), r)
}

type FullUser struct {
	UID         uint `gorm:"auto_increment;primary_key"`
	Mail        string
	EncPassword string
	Username    string
	Role        bool
}

func (u FullUser) GetID() uint {
	return u.UID
}

func (u FullUser) GetEmail() string {
	return u.Mail
}

func (u FullUser) GetPassword() string {
	return u.EncPassword
}

func (FullUser) TableName() string {
	return "user"
}

func (FullUser) EmailColumnName() string {
	return "mail"
}

func (user *FullUser) ID(id uint) {
	user.UID = id
}

func (user *FullUser) Email(email string) {
	user.Mail = email
}

func (user *FullUser) Password(password string) {
	user.EncPassword = password
}

func (u FullUser) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID        uint   `json:"id"`
		Mail      string `json:"mail"`
		Username  string `json:"username"`
		RandToken string `json:"rand_token"`
	}{
		ID:        u.UID,
		Mail:      u.Mail,
		Username:  u.Username,
		RandToken: "RAND TOKEN",
	})
}

func TestLoginWithCustomUser(t *testing.T) {
	setEnvVars()
	db, _ := gorm.Open(os.Getenv("DB_DIALECT"), os.Getenv("DB_CONNECTION"))
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("querty"), bcrypt.DefaultCost)
	user := FullUser{Mail: "hanfry@sample.com", Username: "hanfry", EncPassword: string(hashedPassword)}
	db.AutoMigrate(&user)
	db.Create(&user)
	server := NewServerWithOpts(&Conf{DB: db, UserModel: &FullUser{}})
	recorder := httptest.NewRecorder()
	userID := user.UID

	payload := []byte(`{"email":"hanfry@sample.com","password":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.HeaderMap["Content-Type"][0])
	assert.NotEmpty(t, recorder.HeaderMap["X-Token"][0])

	user = FullUser{}
	json.Unmarshal(recorder.Body.Bytes(), &user)
	responseJson := fmt.Sprintf("{\"id\":%d,\"mail\":\"hanfry@sample.com\",\"username\":\"hanfry\",\"rand_token\":\"RAND TOKEN\"}\n", userID)
	assert.Equal(t, responseJson, string(recorder.Body.Bytes()))
}

func TestRegistrationWithCustomUser(t *testing.T) {
	setEnvVars()
	db, _ := gorm.Open(os.Getenv("DB_DIALECT"), os.Getenv("DB_CONNECTION"))
	db.AutoMigrate(&FullUser{})
	server := NewServerWithOpts(&Conf{DB: db, UserModel: &FullUser{}})
	recorder := httptest.NewRecorder()

	payload := []byte(`{"email":"hanfry@sample.com","password":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Nil(t, recorder.HeaderMap["X-Token"])

	user := FullUser{}
	server.DB.Last(&user)
	assert.Equal(t, "hanfry@sample.com", user.Mail)
	assert.NotEmpty(t, user.EncPassword)
	assert.NotEmpty(t, user.UID)
}
