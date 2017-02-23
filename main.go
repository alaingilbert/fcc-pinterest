package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/asaskevich/govalidator"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/twitter"
	"github.com/urfave/cli"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"html/template"
	"io"
	"net/http"
	"os"
	"time"
)

type H map[string]interface{}

var session *mgo.Session
var authTokenCookieName = "auth-token"
var dbname string

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	var files []string
	files = append(files, "templates/base.html")
	files = append(files, fmt.Sprintf("templates/%s.html", name))
	tmpl := template.Must(template.ParseFiles(files...))
	return tmpl.Execute(w, data)
}

type User struct {
	ID                 bson.ObjectId `bson:"_id"`
	NickName           string
	TwitterID          string
	SessionKey         string
	TwitterAccessToken string
	TwitterAvatarURL   string
	Name               string
}

type Image struct {
	ID          bson.ObjectId `bson:"_id"`
	URL         string
	Description string
	Owner       string
	OwnerAvatar string
}

func NewUserFromGothUser(gothUser goth.User) *User {
	u := new(User)
	u.ID = bson.NewObjectId()
	u.NickName = gothUser.NickName
	u.TwitterID = gothUser.UserID
	u.SessionKey = ""
	u.TwitterAccessToken = gothUser.AccessToken
	u.TwitterAvatarURL = gothUser.AvatarURL
	u.Name = gothUser.Name
	return u
}

func GetUser(userID string) (User, error) {
	s := session.Copy()
	defer s.Close()
	usersCollection := s.DB(dbname).C("users")
	var user User
	err := usersCollection.Find(bson.M{"twitterid": userID}).One(&user)
	return user, err
}

func mainHandler(c echo.Context) error {
	s := session.Copy()
	defer s.Close()
	imagesCollection := s.DB(dbname).C("images")
	var images []Image
	if err := imagesCollection.Find(bson.M{}).All(&images); err != nil {
	}
	data := H{"user": c.Get("user"), "images": images}
	return c.Render(200, "index", data)
}

func userBoardHandler(c echo.Context) error {
	userID := c.Param("userID")
	s := session.Copy()
	defer s.Close()
	imagesCollection := s.DB(dbname).C("images")
	var images []Image
	if err := imagesCollection.Find(bson.M{"owner": userID}).All(&images); err != nil {
	}
	data := H{"user": c.Get("user"), "images": images}
	return c.Render(200, "index", data)
}

func newImageHandler(c echo.Context) error {
	user := c.Get("user").(User)
	data := H{"user": user, "url": "", "description": ""}
	return c.Render(200, "add-image", data)
}

func createImageHandler(c echo.Context) error {
	user := c.Get("user").(User)
	imageURL := c.FormValue("url")
	imageDescription := c.FormValue("description")
	if !govalidator.IsURL(imageURL) {
		data := H{"user": user, "url": imageURL, "description": imageDescription}
		data["error"] = "Image URL is invalid"
		return c.Render(200, "add-image", data)
	}
	s := session.Copy()
	defer s.Close()
	imagesCollection := s.DB(dbname).C("images")
	image := Image{}
	image.ID = bson.NewObjectId()
	image.URL = imageURL
	image.Description = imageDescription
	image.Owner = user.TwitterID
	image.OwnerAvatar = user.TwitterAvatarURL
	if err := imagesCollection.Insert(image); err != nil {
		fmt.Println("unable to create image", err)
		return c.String(500, "Unable to create image")
	}
	return c.Redirect(303, "/my-images")
}

func myImagesHandler(c echo.Context) error {
	user := c.Get("user").(User)
	s := session.Copy()
	defer s.Close()
	imagesCollection := s.DB(dbname).C("images")
	var images []Image
	imagesCollection.Find(bson.M{"owner": user.TwitterID}).All(&images)
	data := H{"user": user, "images": images}
	return c.Render(200, "index", data)
}

func deleteImageHandler(c echo.Context) error {
	user := c.Get("user").(User)
	imageID := c.Param("imageID")
	if !bson.IsObjectIdHex(imageID) {
		return c.String(400, "Bad image id")
	}
	s := session.Copy()
	defer s.Close()
	imagesCollection := s.DB(dbname).C("images")
	if err := imagesCollection.Remove(bson.M{"owner": user.TwitterID, "_id": bson.ObjectIdHex(imageID)}); err != nil {
		return c.String(400, "Image does not exists")
	}
	return c.Redirect(303, "/my-images")
}

func GenerateToken() string {
	// This error can safely be ignored.
	// Only crash when year is outside of [0,9999]
	key, _ := time.Now().MarshalText()
	token := hex.EncodeToString(hmac.New(sha256.New, key).Sum(nil))
	return token
}

func SetUserAuthToken(gothUser goth.User, token string) error {
	s := session.Copy()
	defer s.Close()
	usersCollection := s.DB(dbname).C("users")
	if err := usersCollection.Update(bson.M{"twitterid": gothUser.UserID}, bson.M{"$set": bson.M{"sessionkey": token}}); err != nil {
		u := NewUserFromGothUser(gothUser)
		u.SessionKey = token
		if err := usersCollection.Insert(*u); err != nil {
			if !mgo.IsDup(err) {
				return err
			}
		}
	}
	return nil
}

func authTwitterHandler(c echo.Context) error {
	// try to get the user without re-authenticating
	res := c.Response()
	req := c.Request()
	if gothUser, err := gothic.CompleteUserAuth(res, req); err == nil {
		token := GenerateToken()
		if err := SetUserAuthToken(gothUser, token); err != nil {
			return err
		}
		cookie := http.Cookie{Name: authTokenCookieName, Value: token, Path: "/"}
		c.SetCookie(&cookie)
		return c.Redirect(303, "/")
	} else {
		gothic.BeginAuthHandler(res, req)
		return nil
	}
}

func authTwitterCallbackHandler(c echo.Context) error {
	gothUser, err := gothic.CompleteUserAuth(c.Response(), c.Request())
	if err != nil {
		return err
	}
	token := GenerateToken()
	if err := SetUserAuthToken(gothUser, token); err != nil {
		return err
	}
	cookie := http.Cookie{Name: authTokenCookieName, Value: token, Path: "/"}
	c.SetCookie(&cookie)
	return c.Redirect(303, "/")
}

func logoutHandler(c echo.Context) error {
	//cookie1 := &http.Cookie{
	//  Name:   fmt.Sprintf("twitter%s", gothic.SessionName),
	//  Value:  "",
	//  Path:   "/",
	//  MaxAge: -1,
	//}
	//c.SetCookie(&cookie1)
	cookie := http.Cookie{Name: authTokenCookieName, Value: "", Path: "/"}
	c.SetCookie(&cookie)
	return c.Redirect(302, "/")
}

func ensureIndex() {
	s := session.Copy()
	defer s.Close()
	c := s.DB(dbname).C("users")
	index := mgo.Index{
		Key:        []string{"twitterid"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
	err := c.EnsureIndex(index)
	if err != nil {
		panic(err)
	}
}

// IsAuthMiddleware will ensure user is authenticated.
// - Find user from context
// - If user is empty, redirect to home
func IsAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user").(User)
		if user.TwitterID == "" {
			return c.Redirect(302, "/")
		}
		return next(c)
	}
}

// SetUserMiddleware Get user and put it into echo context.
// - Get auth-token from cookie
// - If exists, get user from database
// - If found, set user in echo context
// - Otherwise, empty user will be put in context
func SetUserMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var user User
		authCookie, err := c.Cookie(authTokenCookieName)
		if err != nil {
			c.Set("user", user)
			return next(c)
		}
		s := session.Copy()
		defer s.Close()
		usersCollection := s.DB(dbname).C("users")
		if err := usersCollection.Find(bson.M{"sessionkey": authCookie.Value}).One(&user); err != nil {
		}
		c.Set("user", user)
		return next(c)
	}
}

func getProvider(req *http.Request) (string, error) {
	return "twitter", nil
}

func start(c *cli.Context) error {
	goth.UseProviders(
		twitter.NewAuthenticate(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), os.Getenv("TWITTER_CALLBACK")),
	)
	gothic.Store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	gothic.GetProviderName = getProvider

	dbname = os.Getenv("MONGODB_DBNAME")
	var err error
	session, err = mgo.Dial(os.Getenv("MONGODB_URI"))
	if err != nil {
		return err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	ensureIndex()

	t := &Template{}
	port := c.Int("port")
	e := echo.New()
	e.Static("/public", "public")
	e.Use(SetUserMiddleware)
	e.Renderer = t
	e.Debug = true
	e.Logger.SetLevel(log.INFO)
	e.GET("/", mainHandler)
	e.GET("/auth/twitter", authTwitterHandler)
	e.GET("/auth/twitter/callback", authTwitterCallbackHandler)
	e.GET("/logout", logoutHandler)
	e.GET("/users/:userID", userBoardHandler)

	needAuthGroup := e.Group("")
	needAuthGroup.Use(IsAuthMiddleware)
	needAuthGroup.GET("/my-images", myImagesHandler)
	needAuthGroup.GET("/add-image", newImageHandler)
	needAuthGroup.POST("/images/new", createImageHandler)
	needAuthGroup.GET("/images/delete/:imageID", deleteImageHandler)

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))
	return nil
}

func main() {
	app := cli.NewApp()
	app.Author = "Alain Gilbert"
	app.Email = "alain.gilbert.15@gmail.com"
	app.Name = "FCC pinterest app"
	app.Usage = "FCC pinterest app"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:   "port",
			Value:  3001,
			Usage:  "Webserver port",
			EnvVar: "PORT",
		},
	}
	app.Action = start
	app.Run(os.Args)
}
