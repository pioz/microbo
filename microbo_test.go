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

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setEnvVars() {
	os.Setenv("CERT_FILE", "./cert/localhost+1.pem")
	os.Setenv("CERT_KEY", "./cert/localhost+1-key.pem")
	os.Setenv("DB_CONNECTION", ":memory:")
	os.Setenv("ROOT_PATH", "./fixtures/public")
	os.Setenv("ROOT_PATH_ENDPOINT", "/public/")
	os.Setenv("SERVER_ADDR", "127.0.0.1:3000")
}

func populateDB() *gorm.DB {
	db, _ := gorm.Open(sqlite.Open(os.Getenv("DB_CONNECTION")), nil)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("querty"), bcrypt.DefaultCost)
	user := DefaultUser{Email: "pioz@sample.com", Password: string(hashedPassword)}
	err := db.AutoMigrate(&user)
	if err != nil {
		panic(err)
	}
	db.Create(&user)
	return db
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	err := encoder.Encode("pong")
	if err != nil {
		panic(err)
	}
}

func TestGetRequestHandler(t *testing.T) {
	setEnvVars()
	db := populateDB()
	server := NewServer(db)
	server.HandleFunc("GET", "/ping", handlePing)
	recorder := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/ping", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

	var r string
	err := json.Unmarshal(recorder.Body.Bytes(), &r)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "pong", r)
}

type CustomServer struct {
	*Server
	Data string
}

func NewCustomServer(data string) *CustomServer {
	return &CustomServer{
		Server: NewServer(nil),
		Data:   data,
	}
}

func (server *CustomServer) handlePingCustomServer(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	err := encoder.Encode(server.Data)
	if err != nil {
		panic(err)
	}
}

func TestHelloWorldWithCustomServer(t *testing.T) {
	setEnvVars()
	server := NewCustomServer("pong")
	server.HandleFunc("GET", "/ping", server.handlePingCustomServer)
	recorder := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/ping", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

	var r string
	err := json.Unmarshal(recorder.Body.Bytes(), &r)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "pong", r)
}

func TestGetStaticFile(t *testing.T) {
	setEnvVars()
	server := NewServer(nil)
	recorder := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/public/images/eld_197.png", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "image/png", recorder.Header().Get("Content-Type"))
}

func Test404StaticFile(t *testing.T) {
	setEnvVars()
	server := NewServer(nil)
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
	assert.Empty(t, recorder.Header().Get("X-Token"))

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
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.NotEmpty(t, recorder.Header().Get("X-Token"))

	user := DefaultUser{}
	err := json.Unmarshal(recorder.Body.Bytes(), &user)
	if err != nil {
		t.Fatal(err)
	}
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
	token := recorder.Header().Get("X-Token")

	time.Sleep(time.Second)

	recorder = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/auth/refresh", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.NotEqual(t, token, recorder.Header().Get("X-Token"))
}

func TestNoAuthIfNoValidUserTable(t *testing.T) {
	setEnvVars()
	server := NewServer(nil)
	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/auth/login", nil)
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func authPingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	userId := r.Context().Value("user_id").(uint)
	encoder := json.NewEncoder(w)
	err := encoder.Encode(fmt.Sprintf("pong %d", userId))
	if err != nil {
		panic(err)
	}
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
	token := recorder.Header().Get("X-Token")
	fmt.Println(token)

	recorder = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/ping", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

	var r string
	err := json.Unmarshal(recorder.Body.Bytes(), &r)
	if err != nil {
		t.Fatal(err)
	}
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
	db, _ := gorm.Open(sqlite.Open(os.Getenv("DB_CONNECTION")), nil)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("querty"), bcrypt.DefaultCost)
	user := FullUser{Mail: "hanfry@sample.com", Username: "hanfry", EncPassword: string(hashedPassword)}
	err := db.AutoMigrate(&user)
	if err != nil {
		t.Fatal(err)
	}
	db.Create(&user)
	server := NewServerWithOpts(&Conf{DB: db, UserModel: &FullUser{}})
	recorder := httptest.NewRecorder()
	userID := user.UID

	payload := []byte(`{"email":"hanfry@sample.com","password":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.NotEmpty(t, recorder.Header().Get("X-Token"))

	user = FullUser{}
	err = json.Unmarshal(recorder.Body.Bytes(), &user)
	if err != nil {
		t.Fatal(err)
	}
	responseJson := fmt.Sprintf("{\"id\":%d,\"mail\":\"hanfry@sample.com\",\"username\":\"hanfry\",\"rand_token\":\"RAND TOKEN\"}\n", userID)
	assert.Equal(t, responseJson, recorder.Body.String())
}

func TestRegistrationWithCustomUser(t *testing.T) {
	setEnvVars()
	db, _ := gorm.Open(sqlite.Open(os.Getenv("DB_CONNECTION")), nil)
	err := db.AutoMigrate(&FullUser{})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServerWithOpts(&Conf{DB: db, UserModel: &FullUser{}})
	recorder := httptest.NewRecorder()

	payload := []byte(`{"email":"hanfry@sample.com","password":"querty"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(payload))
	server.Router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Header().Get("X-Token"))

	user := FullUser{}
	server.DB.Last(&user)
	assert.Equal(t, "hanfry@sample.com", user.Mail)
	assert.NotEmpty(t, user.EncPassword)
	assert.NotEmpty(t, user.UID)
}
