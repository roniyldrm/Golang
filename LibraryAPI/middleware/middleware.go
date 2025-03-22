package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
)

var jwtSecret = []byte("yourSecretKey") // You can replace this with an environment variable

// JWTMiddleware is used to check the validity of JWT tokens for protected routes
func JWTMiddleware(c *fiber.Ctx) error {
	// Get the token from the Authorization header
	tokenStr := c.Get("Authorization")
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// Parse the JWT token
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing algorithm
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		// Return the secret key to validate the token
		return jwtSecret, nil
	})

	// Check for errors in parsing or if the token is invalid
	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// Store the claims in the context for later use (e.g., GetUser route)
	c.Locals("user", token)

	// Proceed with the request
	return c.Next()
}

// CreateJWTToken generates a new JWT token for a user
func CreateJWTToken(username string) (string, error) {
	// Define token claims
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // 1-day expiration
	}

	// Create a new token with these claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	return token.SignedString(jwtSecret)
}
