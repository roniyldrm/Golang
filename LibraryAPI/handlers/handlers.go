package handlers

import (
	"LibraryAPI/database"
	"LibraryAPI/middleware"
	"LibraryAPI/models"
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func removeAtIndex(slice []string, index int) []string {
	return append(slice[:index], slice[index+1:]...)
}

const (
	StatusOK                  = 200
	StatusCreated             = 201
	StatusBadRequest          = 400
	StatusUnauthorized        = 401
	StatusForbidden           = 403
	StatusNotFound            = 404
	StatusInternalServerError = 500
)

// User Registration
func RegisterUser(c *fiber.Ctx) error {
	coll := database.GetCollection("users")
	type registerDTO struct {
		Username string `json:"username" bson:"username"`
		Password string `json:"password" bson:"password"`
		Email    string `json:"email" bson:"email"`
	}

	u := new(registerDTO)

	if err := c.BodyParser(u); err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid body",
		})
	}

	if u.Username == "" || u.Password == "" || u.Email == "" {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "username, password, and email are required",
		})
	}

	// Check if the username or email already exists
	existingUser := models.User{}
	err := coll.FindOne(c.Context(), bson.M{"$or": []bson.M{
		{"username": u.Username},
		{"email": u.Email},
	}}).Decode(&existingUser)

	if err == nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "username or email already in use",
		})
	}

	//Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to hash password",
		})
	}

	user := models.User{
		ID:       primitive.NewObjectID(),
		Username: u.Username,
		Password: string(hashedPassword),
		Email:    u.Email,
		Borrowed: []string{},
	}

	result, err := coll.InsertOne(c.Context(), user)
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error":   "failed to register the user",
			"message": err.Error(),
		})
	}

	return c.Status(StatusCreated).JSON(fiber.Map{"result": result})

}

// User Login
func LoginUser(c *fiber.Ctx) error {

	type request struct {
		Username string `json:"username" bson:"username"`
		Password string `json:"password" bson:"password"`
	}

	userlogin := new(request)

	if err := c.BodyParser(userlogin); err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid body",
		})
	}

	if userlogin.Username == "" || userlogin.Password == "" {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "username and password are required",
		})
	}

	user := models.User{}

	coll := database.GetCollection("users")

	err := coll.FindOne(c.Context(), bson.M{"username": userlogin.Username}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return c.Status(StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userlogin.Password)); err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{"error": "Invalid username or password"})
	}

	token, err := middleware.CreateJWTToken(userlogin.Username)
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
	}

	return c.Status(StatusOK).JSON(fiber.Map{"token": token})

}

// Account Details
func GetUser(c *fiber.Ctx) error {
	coll := database.GetCollection("users")

	// Extract username from JWT claims (stored in context)
	userToken := c.Locals("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	user := models.User{}

	err := coll.FindOne(c.Context(), bson.M{"username": username}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return c.Status(StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(StatusOK).JSON(user)
}

func DeleteUser(c *fiber.Ctx) error {
	collUser := database.GetCollection("users")
	collBook := database.GetCollection("books")

	id := c.Params("userid")
	if id == "" {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}

	user := models.User{}

	err = collUser.FindOne(c.Context(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	_, err = collBook.UpdateMany(context.Background(), bson.M{"takenBy": objectID}, bson.M{"$set": bson.M{"taken": false, "takenBy": nil}})
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	res, err := collUser.DeleteOne(context.Background(), bson.M{"_id": objectID})
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete user"})
	}
	if res.DeletedCount == 0 {
		return c.Status(StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}

	return c.Status(StatusOK).JSON(fiber.Map{"message": "user deleted succesfully"})
}

func GetBook(c *fiber.Ctx) error {
	coll := database.GetCollection("books")

	id := c.Params("bookid")
	if id == "" {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}

	book := models.Book{}

	err = coll.FindOne(c.Context(), bson.M{"_id": objectID}).Decode(&book)
	if err == mongo.ErrNoDocuments {
		return c.Status(StatusNotFound).JSON(fiber.Map{"error": "book not found"})
	}
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(StatusOK).JSON(fiber.Map{"book": book})
}

func CreateBook(c *fiber.Ctx) error {

	type createDTO struct {
		Title  string `json:"title" bson:"title"`
		Author string `json:"author" bson:"author"`
		Year   int    `json:"year" bson:"year"`
	}

	book := new(createDTO)

	if err := c.BodyParser(book); err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid body",
		})
	}

	b := models.Book{
		ID:     primitive.NewObjectID(),
		Author: book.Author,
		Title:  book.Title,
		Year:   book.Year,
	}

	coll := database.GetCollection("books")
	result, err := coll.InsertOne(c.Context(), b)
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error":   "failed to create book",
			"message": err.Error(),
		})
	}

	return c.Status(StatusCreated).JSON(fiber.Map{"result": result})
}

func GetAllBooks(c *fiber.Ctx) error {
	coll := database.GetCollection("books")

	books := make([]models.Book, 0)
	cursor, err := coll.Find(c.Context(), bson.M{})
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	for cursor.Next(c.Context()) {
		book := models.Book{}
		err := cursor.Decode(&book)
		if err != nil {
			return c.Status(StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		books = append(books, book)
	}

	return c.Status(StatusOK).JSON(fiber.Map{"Books": books})

}

// Borrow a Book
func BorrowBook(c *fiber.Ctx) error {
	collUser := database.GetCollection("users")
	collBook := database.GetCollection("books")

	userid := c.Params("userid")
	bookid := c.Params("bookid")
	if userid == "" || bookid == "" {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}

	book := models.Book{}
	user := models.User{}

	objectIDBook, err := primitive.ObjectIDFromHex(bookid)
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}
	objectIDUser, err := primitive.ObjectIDFromHex(userid)
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}

	err = collBook.FindOne(c.Context(), bson.M{"_id": objectIDBook}).Decode(&book)
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	if book.Taken {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "book is already taken",
		})
	}

	err = collUser.FindOne(c.Context(), bson.M{"_id": objectIDUser}).Decode(&user)
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	if len(user.Borrowed) >= 2 {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "user already has 2 books",
		})
	}

	_, err = collBook.UpdateOne(context.Background(), bson.M{"_id": objectIDBook}, bson.M{"$set": bson.M{"taken": true, "takenBy": objectIDUser}})
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	_, err = collUser.UpdateOne(context.Background(), bson.M{"_id": objectIDUser}, bson.M{"$push": bson.M{"borrowed": book.Title}})
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(StatusOK).JSON(fiber.Map{"message": "book assigned succesfully"})
}

// Return a Book
func ReturnBook(c *fiber.Ctx) error {
	collBook := database.GetCollection("books")
	collUser := database.GetCollection("users")

	userid := c.Params("userid")
	bookid := c.Params("bookid")
	if userid == "" || bookid == "" {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}

	book := models.Book{}
	user := models.User{}

	objectIDBook, err := primitive.ObjectIDFromHex(bookid)
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}
	objectIDUser, err := primitive.ObjectIDFromHex(userid)
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}

	err = collBook.FindOne(c.Context(), bson.M{"_id": objectIDBook}).Decode(&book)
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	//Check if the book is taken and by the correct user
	if book.TakenBy == nil || book.TakenBy.IsZero() {
		return c.Status(StatusBadRequest).JSON(fiber.Map{"error": "book is not borrowed"})
	}

	if *book.TakenBy != objectIDUser {
		return c.Status(StatusBadRequest).JSON(fiber.Map{"error": "book is borrowed by another user"})
	}

	err = collUser.FindOne(c.Context(), bson.M{"_id": objectIDUser}).Decode(&user)
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	_, err = collBook.UpdateOne(context.Background(), bson.M{"_id": objectIDBook}, bson.M{"$set": bson.M{"taken": false, "takenBy": nil}})
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	index := 0
	for i, v := range user.Borrowed {
		if v == book.Title {
			index = i
			break
		}
	}

	_, err = collUser.UpdateOne(context.Background(), bson.M{"_id": objectIDUser}, bson.M{"$set": bson.M{"borrowed": removeAtIndex(user.Borrowed, index)}})
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(StatusOK).JSON(fiber.Map{"message": "book returned succesfully"})
}

func DeleteBook(c *fiber.Ctx) error {
	collUser := database.GetCollection("users")
	collBook := database.GetCollection("books")

	id := c.Params("bookid")
	if id == "" {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": "invalid id",
		})
	}

	book := models.Book{}
	user := models.User{}

	err = collBook.FindOne(c.Context(), bson.M{"_id": objectID}).Decode(&book)
	if err != nil {
		return c.Status(StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	objectIDUser := book.TakenBy

	if book.TakenBy != nil && !book.TakenBy.IsZero() {

		err = collUser.FindOne(c.Context(), bson.M{"_id": objectIDUser}).Decode(&user)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		index := 0
		for i, v := range user.Borrowed {
			if v == book.Title {
				index = i
				break
			}
		}

		_, err = collUser.UpdateOne(context.Background(), bson.M{"_id": objectIDUser}, bson.M{"$set": bson.M{"borrowed": removeAtIndex(user.Borrowed, index)}})
		if err != nil {
			return c.Status(StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

	}

	_, err = collBook.DeleteOne(context.Background(), bson.M{"_id": objectID})
	if err != nil {
		return c.Status(StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(StatusOK).JSON(fiber.Map{"message": "book has been deleted successfully"})
}
