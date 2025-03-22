package routes

import (
	"LibraryAPI/handlers"

	"github.com/gofiber/fiber/v2"
)

func Setup(app fiber.Router) {
	app.Post("/book/create", handlers.CreateBook)

	app.Post("/borrow/user/:userid/book/:bookid", handlers.BorrowBook)
	app.Post("/return/user/:userid/book/:bookid", handlers.ReturnBook)

	app.Post("/book/return/:userid/:bookid", handlers.ReturnBook)
	app.Delete("/user/delete/:userid", handlers.DeleteUser)
	app.Delete("/book/delete/:bookid", handlers.DeleteBook)

	app.Get("/user", handlers.GetUser)
	app.Get("/books", handlers.GetAllBooks)
	app.Get("/book/:bookid", handlers.GetBook)

}
