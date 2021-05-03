package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("loremipsum")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Todo struct {
	Id          int
	Title       string `json:"title"`
	Description string `json:"description"`
}

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "simple"
	dbname   = "postgres"
)

func HashPassword(pass string) (string, error) {
	byteData, err := bcrypt.GenerateFromPassword([]byte(pass), 14)
	return string(byteData), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

var db *sql.DB

func OpenConnection() *sql.DB {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	return db
}

// it will run authentication code
// then run the handler func given in its argument
func AuthRequired(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// authentication code
		// CASE-> when there is no "token" cookie -> Unauthorized
		c, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// CASE-> when there is A "token" cookie-> check if still valid
		// can be invalid if 1. time expired 2. signature does not matches

		tknStr := c.Value
		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			// signature mismatch
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// OR any other error
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// time expired OR token valid but for different user
		if !tkn.Valid || claims.Username != filepath.Base(r.URL.Path) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// authorized now --------------------

		handler.ServeHTTP(w, r)
	}
}

func GetTodos(w http.ResponseWriter, r *http.Request) {

	userName := filepath.Base(r.URL.Path)

	// get id of given username
	var userId int
	getUserId := `SELECT id FROM users WHERE username=$1`
	err := db.QueryRow(getUserId, userName).Scan(&userId)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User does not exists!", http.StatusBadRequest)
			return
		} else {
			w.WriteHeader(http.StatusBadRequest)
			panic(err)
		}
	}

	query := "SELECT id, title, description FROM todos WHERE userid=$1"
	rows, err := db.Query(query, userId)

	if err != nil {
		panic(err)
	}

	var data []Todo

	for rows.Next() {
		var d Todo
		rows.Scan(&d.Id, &d.Title, &d.Description)
		data = append(data, d)
	}

	dataBytes, _ := json.MarshalIndent(data, "", "\t")
	w.Write(dataBytes)

	defer rows.Close()
}

func CreateTodo(w http.ResponseWriter, r *http.Request) {

	userName := filepath.Base(r.URL.Path)

	// extract todo info
	var t Todo
	err := json.NewDecoder(r.Body).Decode(&t)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// get id of given username
	var userId int
	getUserId := `SELECT id FROM users WHERE username=$1`
	err = db.QueryRow(getUserId, userName).Scan(&userId)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User does not exists!", http.StatusBadRequest)
			return
		} else {
			w.WriteHeader(http.StatusBadRequest)
			panic(err)
		}
	}

	sqlStatement := `INSERT INTO todos (title, description, userid) VALUES ($1, $2, $3)`
	_, err = db.Exec(sqlStatement, t.Title, t.Description, userId)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func LogIn(w http.ResponseWriter, r *http.Request) {

	var u User
	err := json.NewDecoder(r.Body).Decode(&u)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var passwdHash string
	checkIfExists := `SELECT password FROM users WHERE username=$1`
	err = db.QueryRow(checkIfExists, u.Username).Scan(&passwdHash)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User does not exists!", http.StatusBadRequest)
			return
		} else {
			w.WriteHeader(http.StatusBadRequest)
			panic(err)
		}
	} else if !CheckPasswordHash(u.Password, passwdHash) {
		http.Error(w, "Incorrect password!", http.StatusUnauthorized)
		return
	}

	// authorised here

	// set username, expiration time
	expirationTime := time.Now().Add(1 * time.Minute)
	claims := &Claims{
		Username: u.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	//generate token with above claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// get token string using signature
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// store token info to cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	w.WriteHeader(http.StatusOK)
}

func PanicError(e error) {
	if err != nil {
		panic(err)
	}
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	var u User
	err := json.NewDecoder(r.Body).Decode(&u)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	u.Password, err = HashPassword(u.Password)
	PanicError(err)

	sqlStatement := `INSERT INTO users (username, password) VALUES ($1, $2)`
	_, err = db.Exec(sqlStatement, u.Username, u.Password)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func initiate() {
	db = OpenConnection()
	defer db.Close()

	http.HandleFunc("/get-todos/", AuthRequired(GetTodos))     // get
	http.HandleFunc("/signup", SignUp)                         // post
	http.HandleFunc("/login", LogIn)                           // post
	http.HandleFunc("/create-todo/", AuthRequired(CreateTodo)) // post
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
	initiate()
}
