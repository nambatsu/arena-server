package main

import (
	_ "database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/srinathgs/mysqlstore"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type Jsondata struct {
	Number int    `json:"number,omitempty"`
	String string `json:"string,omitempty"`
	Bool   bool   `json:"bool,omitempty"`
}

type User struct {
	Username   string `json:"username,omitempty"  db:"userID"`
	HashedPass string `json:"-"  db:"hashed_pass"`
}

type Me struct {
	Name string `json:"name,omitempty" db:"username"`
}

var (
	db *sqlx.DB
)

func main() {
	_db, err := sqlx.Connect("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", os.Getenv("DB_USERNAME"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOSTNAME"), os.Getenv("DB_PORT"), os.Getenv("DB_DATABASE")))
	if err != nil {
		log.Fatalf("Cannot Connect to Database: %s", err)
	}
	db = _db

	store, err := mysqlstore.NewMySQLStoreFromConnection(db.DB, "sessions", "/", 60*60*24*14, []byte("secret-token"))
	if err != nil {
		panic(err)
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(session.Middleware(store))

	e.POST("/post", POST)
	e.POST("/login", login)
	e.POST("/signup", SignUp)
	e.GET("/logout", logout)

	withLogin := e.Group("")
	withLogin.Use(checkLogin)
	withLogin.GET("/json", JSON)
	withLogin.GET("/whoami", whoami)
	withLogin.GET("/hello/:username", func(c echo.Context) error {
		userID := c.Param("username")
		return c.String(http.StatusOK, "Hello,"+userID+".\n")
	})

	e.Start(":4000")
}

type LoginRequestBody struct {
	Username string `json:"username,omitempty" form:"username"`
	Password string `json:"password,omitempty" form:"password"`
}

type SignUpRequestBody struct {
	Name                    string `json:"name,omitempty" form:"name"`
	Username                string `json:"userID,omitempty" form:"userID"`
	Password                string `json:"password,omitempty" form:"password"`
	Shudan_jikyu            string `json:"shudan_jikyu,omitempty" form:"shudan_jikyu"`
	Kobetsu_jikyu           string `json:"kobetsu_jikyu,omitempty" form:"kobetsu_jikyu"`
	Transportation_expenses string `json:"Transportation_expenses,omitempty" form:"Transportation_expenses"`
}

func JSON(c echo.Context) error {
	res := Jsondata{
		Number: 10,
		String: "abc",
		Bool:   true,
	}
	return c.JSON(http.StatusOK, &res)
}

func POST(c echo.Context) error {
	data := new(Jsondata)
	err := c.Bind(data)
	data.Number += 1
	if err != nil {
		return c.JSON(http.StatusBadRequest, data)
	}

	return c.JSON(http.StatusOK, data)
}

func SignUp(c echo.Context) error {
	req := SignUpRequestBody{}
	c.Bind(&req)

	if req.Password == "" || req.Username == "" {
		return c.String(http.StatusBadRequest, "項目が空です")
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("bcrypt generate error: %v", err))
	}

	// ユーザーの存在チェック
	var count int

	err = db.Get(&count, "SELECT COUNT(*) FROM teacher_information WHERE userID=?", req.Username)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
	}

	if count > 0 {
		return c.String(http.StatusConflict, "ユーザーが既に存在しています")
	}

	_, err = db.Exec("INSERT INTO teacher_information (name, userID, hashed_pass, shudan_jikyu, kobetsu_jikyu, transportation_expenses) VALUES (?, ?, ?, ?, ?, ?)", req.Name, req.Username, hashedPass, req.Shudan_jikyu, req.Kobetsu_jikyu, req.Transportation_expenses)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
	}
	return c.NoContent(http.StatusCreated)
}

func login(c echo.Context) error {
	req := LoginRequestBody{}
	c.Bind(&req)

	user := User{}
	err := db.Get(&user, "SELECT userID,hashed_pass FROM teacher_information WHERE userID=?", req.Username)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPass), []byte(req.Password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return c.NoContent(http.StatusForbidden)
		} else {
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	sess, err := session.Get("sessions", c)
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusInternalServerError, "something wrong in getting session")
	}
	sess.Values["userName"] = req.Username
	sess.Save(c.Request(), c.Response())

	return c.String(http.StatusOK, "OK")
}

func checkLogin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("sessions", c)
		if err != nil {
			fmt.Println(err)
			return c.String(http.StatusInternalServerError, "something wrong in getting session")
		}

		if sess.Values["userName"] == nil {
			return c.String(http.StatusForbidden, "please login")
		}
		c.Set("userName", sess.Values["userName"].(string))

		return next(c)
	}
}

func logout(c echo.Context) error {
	sess, err := session.Get("sessions", c)
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusInternalServerError, "something wrong in getting session")
	}

	sess.Values["userName"] = nil
	sess.Save(c.Request(), c.Response())

	return c.NoContent(http.StatusOK)
}

func whoami(c echo.Context) error {
	return c.JSON(http.StatusOK, Me{
		Name: c.Get("userName").(string),
	})
}
