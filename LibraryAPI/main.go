package main

import (
	"LibraryAPI/database"
	"LibraryAPI/handlers"
	"LibraryAPI/middleware"
	"LibraryAPI/routes"
	"log"

	"github.com/gofiber/fiber/v2"
)

func main() {
	database.ConnectDB()

	app := fiber.New()

	app.Post("/register", handlers.RegisterUser)
	app.Post("/login", handlers.LoginUser)

	app.Get("/", func(c *fiber.Ctx) error {
		routes := app.Stack() // This will give you the registered routes
		return c.JSON(fiber.Map{"routes": routes})
	})

	// Group API routes that require authentication
	api := app.Group("/api")
	api.Use(middleware.JWTMiddleware) // ✅ Apply JWT middleware to /api group

	// Set up protected routes under /api
	routes.Setup(api)

	// Start the server
	log.Fatal(app.Listen(":9090"))
}
