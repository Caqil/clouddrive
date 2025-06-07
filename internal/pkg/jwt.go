package pkg

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// JWTManager handles JWT token operations
type JWTManager struct {
	secretKey       []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	issuer          string
	audience        string
}

// TokenClaims represents JWT claims
type TokenClaims struct {
	UserID    primitive.ObjectID `json:"user_id"`
	Email     string             `json:"email"`
	Role      string             `json:"role"`
	TokenType string             `json:"token_type"`
	SessionID string             `json:"session_id"`
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// TokenType constants
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	TokenTypeReset   = "reset"
	TokenTypeVerify  = "verify"
)

// NewJWTManager creates a new JWT manager
func NewJWTManager(secretKey string, accessTTL, refreshTTL time.Duration, issuer, audience string) *JWTManager {
	return &JWTManager{
		secretKey:       []byte(secretKey),
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
		issuer:          issuer,
		audience:        audience,
	}
}

// GenerateTokenPair generates access and refresh tokens
func (jm *JWTManager) GenerateTokenPair(userID primitive.ObjectID, email, role, sessionID string) (*TokenPair, error) {
	now := time.Now()

	// Generate access token
	accessToken, err := jm.generateToken(userID, email, role, sessionID, TokenTypeAccess, now.Add(jm.accessTokenTTL))
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := jm.generateToken(userID, email, role, sessionID, TokenTypeRefresh, now.Add(jm.refreshTokenTTL))
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    now.Add(jm.accessTokenTTL),
		TokenType:    "Bearer",
	}, nil
}

// GenerateResetToken generates a password reset token
func (jm *JWTManager) GenerateResetToken(userID primitive.ObjectID, email string) (string, error) {
	expiresAt := time.Now().Add(1 * time.Hour) // Reset tokens expire in 1 hour
	return jm.generateToken(userID, email, "", "", TokenTypeReset, expiresAt)
}

// GenerateVerificationToken generates an email verification token
func (jm *JWTManager) GenerateVerificationToken(userID primitive.ObjectID, email string) (string, error) {
	expiresAt := time.Now().Add(24 * time.Hour) // Verification tokens expire in 24 hours
	return jm.generateToken(userID, email, "", "", TokenTypeVerify, expiresAt)
}

// generateToken generates a JWT token with the given parameters
func (jm *JWTManager) generateToken(userID primitive.ObjectID, email, role, sessionID, tokenType string, expiresAt time.Time) (string, error) {
	claims := TokenClaims{
		UserID:    userID,
		Email:     email,
		Role:      role,
		TokenType: tokenType,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    jm.issuer,
			Audience:  []string{jm.audience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jm.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates and parses a JWT token
func (jm *JWTManager) ValidateToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jm.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrTokenExpired
	}

	return claims, nil
}

// RefreshToken generates a new access token using a refresh token
func (jm *JWTManager) RefreshToken(refreshTokenString string) (*TokenPair, error) {
	claims, err := jm.ValidateToken(refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.TokenType != TokenTypeRefresh {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	// Generate new token pair
	return jm.GenerateTokenPair(claims.UserID, claims.Email, claims.Role, claims.SessionID)
}

// ExtractTokenFromHeader extracts token from Authorization header
func ExtractTokenFromHeader(authHeader string) string {
	const bearerPrefix = "Bearer "
	if len(authHeader) > len(bearerPrefix) && authHeader[:len(bearerPrefix)] == bearerPrefix {
		return authHeader[len(bearerPrefix):]
	}
	return ""
}
