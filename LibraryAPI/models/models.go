package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	ID       primitive.ObjectID `json:"id" bson:"_id"`
	Username string             `json:"username" bson:"username"`
	Password string             `json:"password" bson:"password"`
	Email    string             `json:"email" bson:"email"`
	Borrowed []string           `json:"borrowed" bson:"borrowed"`
}

type Book struct {
	ID      primitive.ObjectID  `json:"id" bson:"_id"`
	Title   string              `json:"title" bson:"title"`
	Author  string              `json:"author" bson:"author"`
	Year    int                 `json:"year" bson:"year"`
	Taken   bool                `json:"taken" bson:"taken"`
	TakenBy *primitive.ObjectID `json:"takenBy" bson:"takenBy"`
}
