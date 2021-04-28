package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

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
	password = ""
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

func GetTodos(w http.ResponseWriter, r *http.Request) {

	urlEnd := filepath.Base(r.URL.Path)
	userId, err := strconv.Atoi(urlEnd)

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

	var t Todo
	err := json.NewDecoder(r.Body).Decode(&t)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	urlEnd := filepath.Base(r.URL.Path)
	userId, err := strconv.Atoi(urlEnd)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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
		http.Error(w, "Incorrect password!", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	var u User
	err := json.NewDecoder(r.Body).Decode(&u)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	u.Password, err = HashPassword(u.Password)
	if err != nil {
		panic(err)
	}

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

	http.HandleFunc("/get-todos/", GetTodos)     // get
	http.HandleFunc("/signup", SignUp)           // post
	http.HandleFunc("/login", LogIn)             // post
	http.HandleFunc("/create-todo/", CreateTodo) // post
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
	initiate()
}
