package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username" bson:"username"` //json and bson  tags are used to map json fields with the corresponding names during marshalling and unmarshalling
	Password string `json:"password" bson:"password"`
	Notes    string `json:"notes" bson:"notes"`
}

var collection *mongo.Collection
var client *mongo.Client
var database *mongo.Database
var SECRET_KEY = []byte("gosecretkey")

func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

		// Parse the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return SECRET_KEY, nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Verify if the token is valid
		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// If token is valid, call the next handler
		next.ServeHTTP(w, r)
	})
}

func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

func GenerateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, err := token.SignedString(SECRET_KEY)
	if err != nil {
		log.Println("Error in JWT token generation")
		return "", err
	}
	return tokenString, nil
}
func main() {
	router := mux.NewRouter() //creating a new gorilla mux router
	//creating all the routes/ api endpoints
	router.HandleFunc("/login", Login).Methods("POST")
	router.HandleFunc("/register", Register).Methods("POST")
	router.Handle("/getnotes", authenticateMiddleware(http.HandlerFunc(GetNotes))).Methods("GET")
	router.Handle("/deleteuser", authenticateMiddleware(http.HandlerFunc(DeleteUser))).Methods("DELETE")
	router.Handle("/updatenote", authenticateMiddleware(http.HandlerFunc(UpdateNote))).Methods("PUT")
	//router.Handle is used when you want to register a custom handler object that implements the http.Handler interface, while router.HandleFunc is used when you want to define a handler function inline using http.HandlerFunc.
	serverAPI := options.ServerAPI(options.ServerAPIVersion1) // In the MongoDB Go driver, the options.ServerAPI function is used to specify the version of the server API to be used when communicating with a MongoDB server.
	opts := options.Client().ApplyURI("mongodb+srv://kamalpratik:kamal@makenotes.qtyi5iw.mongodb.net/?retryWrites=true&w=majority&appName=MakeNotes").SetServerAPIOptions(serverAPI)
	// Create a new client and connect to the server
	client, err := mongo.Connect(context.Background(), opts)
	if err != nil {
		panic(err)
	}

	defer func() {
		if err = client.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()

	// Send a ping to confirm a successful connection
	if err := client.Database("admin").RunCommand(context.TODO(), bson.D{{"ping", 1}}).Err(); err != nil {
		panic(err)
	}
	fmt.Println("Pinged your deployment. You successfully connected to MongoDB!")
	fmt.Println("Server listening on port 8000")
	log.Fatal(http.ListenAndServe(":8000", router))

}

func Login(w http.ResponseWriter, r *http.Request) {
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	w.Header().Set("Content-Type", "application/json")
	opts := options.Client().ApplyURI("mongodb+srv://kamalpratik:kamal@makenotes.qtyi5iw.mongodb.net/?retryWrites=true&w=majority&appName=MakeNotes").SetServerAPIOptions(serverAPI)
	client, err := mongo.Connect(context.Background(), opts)
	database := client.Database("MakeNotes")

	// Access the "users" collection
	collection := database.Collection("users")

	var user User
	errr := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, errr.Error(), http.StatusBadRequest)
		return
	}
	var result User
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = collection.FindOne(ctx, bson.M{"username": user.Username}).Decode(&result)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}

	// if result.Password != user.Password {
	// 	http.Error(w, "Invalid username or password", http.StatusUnauthorized)
	// 	return
	// }
	passErr := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password)) //compares the encrypted and decrypted password
	if passErr != nil {
		log.Println(passErr)
		w.Write([]byte(`{"response":"Wrong Password!"}`))
		return
	}

	jwtToken, err := GenerateJWT()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}
	w.Write([]byte(`{"token":"` + jwtToken + `"}`))

	fmt.Fprintf(w, "Login Successful! Welcome, %s\n", result.Username)
}

func Register(w http.ResponseWriter, r *http.Request) {
	var user User
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	w.Header().Set("Content-Type", "application/json")
	opts := options.Client().ApplyURI("mongodb+srv://kamalpratik:kamal@makenotes.qtyi5iw.mongodb.net/?retryWrites=true&w=majority&appName=MakeNotes").SetServerAPIOptions(serverAPI)
	client, err := mongo.Connect(context.Background(), opts)
	database := client.Database("MakeNotes")

	// Access the "users" collection
	collection := database.Collection("users")
	json.NewDecoder(r.Body).Decode(&user)
	user.Password = getHash([]byte(user.Password))
	// ctx, _ := context.WithTimeout(context.Background(),
	// 	10*time.Second)
	result, err := collection.InsertOne(context.Background(), user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}
	json.NewEncoder(w).Encode(result) //this line of code creates a new JSON encoder that writes to an http.ResponseWriter and then encodes the result data structure into JSON format, writing the JSON-encoded data to the HTTP response.
	fmt.Println(result)
}

func GetNotes(w http.ResponseWriter, r *http.Request) {
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	w.Header().Set("Content-Type", "application/json")
	opts := options.Client().ApplyURI("mongodb+srv://kamalpratik:kamal@makenotes.qtyi5iw.mongodb.net/?retryWrites=true&w=majority&appName=MakeNotes").SetServerAPIOptions(serverAPI)
	client, err := mongo.Connect(context.Background(), opts)
	database := client.Database("MakeNotes")

	// Access the "users" collection
	collection := database.Collection("users")

	var user User
	errr := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, errr.Error(), http.StatusBadRequest)
		return
	}
	var result User
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = collection.FindOne(ctx, bson.M{"username": user.Username}).Decode(&result)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}

	// passErr := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))
	// if passErr != nil {
	// 	log.Println(passErr)
	// 	w.Write([]byte(`{"response":"Wrong Password!"}`))
	// 	return
	// }

	fmt.Fprintf(w, "Notes : %s\n", result.Notes)

}
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	w.Header().Set("Content-Type", "application/json")
	opts := options.Client().ApplyURI("mongodb+srv://kamalpratik:kamal@makenotes.qtyi5iw.mongodb.net/?retryWrites=true&w=majority&appName=MakeNotes").SetServerAPIOptions(serverAPI)
	client, err := mongo.Connect(context.Background(), opts)
	database := client.Database("MakeNotes")

	// Access the "users" collection
	collection := database.Collection("users")

	var user User
	errr := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, errr.Error(), http.StatusBadRequest)
		return
	}
	var result User
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = collection.FindOne(ctx, bson.M{"username": user.Username}).Decode(&result)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}

	passErr := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))
	if passErr != nil {
		log.Println(passErr)
		w.Write([]byte(`{"response":"Wrong Password!"}`))
		return
	} else {

		o := options.Delete().SetHint(bson.D{{"_id", 1}})
		results, err := collection.DeleteOne(context.TODO(), result, o)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(w, "User Deleted: %s\n", result.Username)
		fmt.Fprintf(w, "Number of documents deleted: %d\n", results.DeletedCount)

	}
}
func UpdateNote(w http.ResponseWriter, r *http.Request) {
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	w.Header().Set("Content-Type", "application/json")
	opts := options.Client().ApplyURI("mongodb+srv://kamalpratik:kamal@makenotes.qtyi5iw.mongodb.net/?retryWrites=true&w=majority&appName=MakeNotes").SetServerAPIOptions(serverAPI)
	client, err := mongo.Connect(context.Background(), opts)
	database := client.Database("MakeNotes")

	// Access the "users" collection
	collection := database.Collection("users")

	var user User
	errr := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, errr.Error(), http.StatusBadRequest)
		return
	}
	var result User
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = collection.FindOne(ctx, bson.M{"username": user.Username}).Decode(&result)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}

	// passErr := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))
	// if passErr != nil {
	// 	log.Println(passErr)
	// 	w.Write([]byte(`{"response":"Wrong Password!"}`))
	// 	return
	// } else {
	update := bson.M{
		"$set": bson.M{
			"notes": user.Notes,
		},
	}
	_, errrr := collection.UpdateOne(context.Background(), result, update)
	if errrr != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(w, "Note Updated for %s\n", result.Username)

}
