package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	_ "incident-tracker/docs"
)

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Email        string    `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string    `gorm:"not null" json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}
type Incident struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Title       string    `gorm:"size:100;not null" json:"title"`
	Description string    `gorm:"type:text;not null" json:"description"`
	Priority    string    `gorm:"size:20;not null" json:"priority"`
	Status      string    `gorm:"size:20;not null;default:open" json:"status"`
	UserID      uint      `gorm:"not null;index" json:"user_id"`
	User        User      `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT" json:"-"`
	CreatedAt   time.Time `json:"created_at"`
}
type Credentials struct {
	Email    string `json:"email" binding:"required,email,max=254"`
	Password string `json:"password" binding:"required,min=6,max=72"`
}
type CreateIncidentDTO struct {
	Title       string `json:"title" binding:"required,min=3,max=100"`
	Description string `json:"description" binding:"required"`
	Priority    string `json:"priority" binding:"required,oneof=low medium high critical"`
}
type StatusDTO struct {
	Status string `json:"status" binding:"required,oneof=open in_progress resolved closed"`
}
type ErrorResponse struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
}
type TokenResponse struct {
	Token string `json:"token"`
}
type Claims struct {
	UserID uint `json:"userID"`
	jwt.RegisteredClaims
}
type Server struct {
	db     *gorm.DB
	secret []byte
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func bad(c *gin.Context, err error) {
	fields := map[string]string{}
	var ve validator.ValidationErrors
	if errors.As(err, &ve) {
		for _, e := range ve {
			field := strings.ToLower(e.Field())
			fields[field] = e.Tag()
			if e.Param() != "" {
				fields[field] += ": " + e.Param()
			}
		}
	}
	c.JSON(400, ErrorResponse{Error: "Некоректні дані запиту", Fields: fields})
}
func dbError(c *gin.Context, err error) {
	log.Printf("database error: %v", err)
	c.JSON(500, ErrorResponse{Error: "Помилка бази даних"})
}
func (s *Server) auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		fail := func() { c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"}) }
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			fail()
			return
		}
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(strings.TrimPrefix(h, "Bearer "), claims, func(t *jwt.Token) (interface{}, error) { return s.secret, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
		if err != nil || !token.Valid || claims.UserID == 0 {
			fail()
			return
		}
		c.Set("userID", claims.UserID)
		c.Next()
	}
}

// register godoc
// @Summary Реєстрація користувача
// @Tags auth
// @Accept json
// @Produce json
// @Param input body Credentials true "Облікові дані"
// @Success 201 {object} User
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /auth/register [post]
func (s *Server) register(c *gin.Context) {
	var d Credentials
	if err := c.ShouldBindJSON(&d); err != nil {
		bad(c, err)
		return
	}
	d.Email = strings.ToLower(strings.TrimSpace(d.Email))
	hash, err := bcrypt.GenerateFromPassword([]byte(d.Password), bcrypt.DefaultCost)
	if err != nil {
		bad(c, err)
		return
	}
	u := User{Email: d.Email, PasswordHash: string(hash)}
	if err = s.db.Create(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			c.JSON(409, ErrorResponse{Error: "Email уже зареєстровано"})
			return
		}
		dbError(c, err)
		return
	}
	c.JSON(201, u)
}

// login godoc
// @Summary Вхід та отримання JWT
// @Tags auth
// @Accept json
// @Produce json
// @Param input body Credentials true "Облікові дані"
// @Success 200 {object} TokenResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/login [post]
func (s *Server) login(c *gin.Context) {
	var d Credentials
	if err := c.ShouldBindJSON(&d); err != nil {
		bad(c, err)
		return
	}
	var u User
	err := s.db.Where("email = ?", strings.ToLower(strings.TrimSpace(d.Email))).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(401, ErrorResponse{Error: "Невірний email або пароль"})
		return
	}
	if err != nil {
		dbError(c, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(d.Password)) != nil {
		c.JSON(401, ErrorResponse{Error: "Невірний email або пароль"})
		return
	}
	now := time.Now()
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{UserID: u.ID, RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour))}})
	signed, err := t.SignedString(s.secret)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: "Помилка створення токена"})
		return
	}
	c.JSON(200, TokenResponse{Token: signed})
}

// list godoc
// @Summary Перелік інцидентів
// @Tags incidents
// @Produce json
// @Success 200 {array} Incident
// @Router /incidents [get]
func (s *Server) list(c *gin.Context) {
	incidents := []Incident{}
	if err := s.db.Find(&incidents).Error; err != nil {
		dbError(c, err)
		return
	}
	c.JSON(200, incidents)
}
func (s *Server) find(c *gin.Context) (*Incident, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		c.JSON(400, ErrorResponse{Error: "Некоректний ID"})
		return nil, false
	}
	var incident Incident
	err = s.db.First(&incident, uint(id)).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(404, ErrorResponse{Error: "Інцидент не знайдено"})
		return nil, false
	}
	if err != nil {
		dbError(c, err)
		return nil, false
	}
	return &incident, true
}

// get godoc
// @Summary Отримати інцидент
// @Tags incidents
// @Produce json
// @Param id path int true "ID"
// @Success 200 {object} Incident
// @Failure 404 {object} ErrorResponse
// @Router /incidents/{id} [get]
func (s *Server) get(c *gin.Context) {
	if i, ok := s.find(c); ok {
		c.JSON(200, i)
	}
}

// create godoc
// @Summary Створити інцидент
// @Tags incidents
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param input body CreateIncidentDTO true "Інцидент"
// @Success 201 {object} Incident
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /incidents [post]
func (s *Server) create(c *gin.Context) {
	var d CreateIncidentDTO
	if err := c.ShouldBindJSON(&d); err != nil {
		bad(c, err)
		return
	}
	if strings.TrimSpace(d.Title) == "" || strings.TrimSpace(d.Description) == "" {
		c.JSON(400, ErrorResponse{Error: "Назва та опис не можуть бути порожніми"})
		return
	}
	i := Incident{Title: d.Title, Description: d.Description, Priority: d.Priority, Status: "open", UserID: c.MustGet("userID").(uint)}
	if err := s.db.Create(&i).Error; err != nil {
		dbError(c, err)
		return
	}
	c.JSON(201, i)
}

// update godoc
// @Summary Змінити статус
// @Tags incidents
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "ID"
// @Param input body StatusDTO true "Статус"
// @Success 200 {object} Incident
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /incidents/{id}/status [patch]
func (s *Server) update(c *gin.Context) {
	var d StatusDTO
	if err := c.ShouldBindJSON(&d); err != nil {
		bad(c, err)
		return
	}
	i, ok := s.find(c)
	if !ok {
		return
	}
	if err := s.db.Model(i).Update("status", d.Status).Error; err != nil {
		dbError(c, err)
		return
	}
	c.JSON(200, i)
}

// delete godoc
// @Summary Видалити інцидент
// @Tags incidents
// @Security BearerAuth
// @Param id path int true "ID"
// @Success 204
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /incidents/{id} [delete]
func (s *Server) delete(c *gin.Context) {
	i, ok := s.find(c)
	if !ok {
		return
	}
	result := s.db.Delete(i)
	if result.Error != nil {
		dbError(c, result.Error)
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(404, ErrorResponse{Error: "Інцидент не знайдено"})
		return
	}
	c.Status(204)
}

// @title Incident Tracker API
// @version 1.0
// @description REST API обліку технічних інцидентів.
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Введіть Bearer та JWT-токен через пробіл.
func main() {
	secret := os.Getenv("JWT_SECRET")
	if len(secret) < 32 {
		log.Fatal("JWT_SECRET має містити щонайменше 32 символи")
	}
	dsn := env("DATABASE_URL", "host=localhost user=postgres password=postgres dbname=incident_tracker port=5432 sslmode=disable")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{TranslateError: true})
	if err != nil {
		log.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}
	defer sqlDB.Close()
	if err = sqlDB.Ping(); err != nil {
		log.Fatal(err)
	}
	if err = db.AutoMigrate(&User{}, &Incident{}); err != nil {
		log.Fatal(err)
	}
	s := Server{db: db, secret: []byte(secret)}
	r := gin.Default()
	v := r.Group("/api/v1")
	v.POST("/auth/register", s.register)
	v.POST("/auth/login", s.login)
	v.GET("/incidents", s.list)
	v.GET("/incidents/:id", s.get)
	protected := v.Group("")
	protected.Use(s.auth())
	protected.POST("/incidents", s.create)
	protected.PATCH("/incidents/:id/status", s.update)
	protected.DELETE("/incidents/:id", s.delete)
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	addr := "127.0.0.1:" + env("PORT", "8080")
	log.Print("PostgreSQL connected and schema migrated")
	log.Printf("Swagger: http://%s/swagger/index.html", addr)
	if err = r.Run(addr); err != nil {
		log.Fatal(err)
	}
}
