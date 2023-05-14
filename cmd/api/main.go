package main

import (
	"context"
	"database/sql"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/IfedayoAwe/chitchat-backend/internal/data"
	"github.com/IfedayoAwe/chitchat-backend/internal/jsonlog"
	"github.com/IfedayoAwe/chitchat-backend/internal/mailer"
	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
)

// do not remove or modify
var (
	buildTime string
	version   string
)

type config struct {
	port int
	env  string
	db   struct {
		dsn          string
		maxOpenConns int
		maxIdleConns int
		maxIdleTime  string
	}
	limiter struct {
		rps     float64
		burst   int
		enabled bool
	}
	metrics struct {
		enabled bool
	}
	profile struct {
		enabled bool
	}
	smtp struct {
		host     string
		port     int
		username string
		password string
		sender   string
		enabled  bool
	}
	cors struct {
		trustedOrigins []string
	}
	jwt struct {
		secret string
	}
	redis struct {
		addr     string
		password string
	}
	otp struct {
		issuer string
		period uint
	}
}

type application struct {
	config config
	logger *jsonlog.Logger
	mailer mailer.Mailer
	models data.Models
	redis  *redis.Client
	wg     sync.WaitGroup
}

func main() {
	path := "images/profile"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}

	var cfg config
	flag.IntVar(&cfg.port, "port", 4000, "API server port")
	flag.StringVar(&cfg.env, "env", "development", "Environment (development|staging|production)")
	flag.StringVar(&cfg.db.dsn, "db-dsn", os.Getenv("CHITCHAT_DB_DSN"), "PostgreSQL DSN")
	flag.IntVar(&cfg.db.maxOpenConns, "db-max-open-conns", 25, "PostgreSQL max open connections")
	flag.IntVar(&cfg.db.maxIdleConns, "db-max-idle-conns", 25, "PostgreSQL max idle connections")
	flag.StringVar(&cfg.db.maxIdleTime, "db-max-idle-time", "15m", "PostgreSQL max connection idle time")
	flag.Float64Var(&cfg.limiter.rps, "limiter-rps", 2, "Rate limiter maximum requests per second")
	flag.IntVar(&cfg.limiter.burst, "limiter-burst", 4, "Rate limiter maximum burst")
	flag.BoolVar(&cfg.limiter.enabled, "limiter-enabled", true, "Enable rate limiter")
	flag.BoolVar(&cfg.metrics.enabled, "metrics-enabled", true, "Enable metrics")
	flag.BoolVar(&cfg.profile.enabled, "profile-enabled", true, "Enable profile")
	flag.StringVar(&cfg.smtp.host, "smtp-host", os.Getenv("SMTP_HOST"), "SMTP host")
	flag.IntVar(&cfg.smtp.port, "smtp-port", 2525, "SMTP port")
	flag.StringVar(&cfg.smtp.username, "smtp-username", os.Getenv("SMTP_USERNAME"), "SMTP username")
	flag.StringVar(&cfg.smtp.password, "smtp-password", os.Getenv("SMTP_PASSWORD"), "SMTP password")
	flag.StringVar(&cfg.smtp.sender, "smtp-sender", os.Getenv("CHITCHAT_SMTP_SENDER"), "SMTP sender")
	flag.BoolVar(&cfg.smtp.enabled, "smtp-enabled", true, "Enable SMTP")
	flag.Func("cors-trusted-origins", "Trusted CORS origins (space separated)", func(val string) error {
		cfg.cors.trustedOrigins = strings.Fields(val)
		return nil
	})
	flag.StringVar(&cfg.jwt.secret, "jwt-secret", "", "JWT secret")
	flag.StringVar(&cfg.redis.addr, "redis-addr", os.Getenv("REDIS_ADDR"), "Redis ADDR")
	flag.StringVar(&cfg.redis.password, "redis-pass", os.Getenv("REDIS_PASS"), "Redis Password")
	flag.StringVar(&cfg.otp.issuer, "otp-issuer", "github.com/IfedayoAwe/chitchat-backend", "OTP issuer")
	flag.UintVar(&cfg.otp.period, "otp-period", 60, "OTP validity period 60 sec")

	displayVersion := flag.Bool("version", false, "Display version and exit")
	flag.Parse()

	if *displayVersion {
		fmt.Printf("Version:\t%s\n", version)
		fmt.Printf("Build time:\t%s\n", buildTime)
		os.Exit(0)
	}

	logger := jsonlog.New(os.Stdout, jsonlog.LevelInfo)

	db, err := openDB(cfg)
	if err != nil {
		logger.PrintFatal(err, nil)
	}
	defer db.Close()

	logger.PrintInfo("database connection pool established", nil)

	expvar.NewString("version").Set(version)
	// Publish the number of active goroutines.
	expvar.Publish("goroutines", expvar.Func(func() interface{} {
		return runtime.NumGoroutine()
	}))
	// Publish the database connection pool statistics.
	expvar.Publish("database", expvar.Func(func() interface{} {
		return db.Stats()
	}))
	// Publish the current Unix timestamp.
	expvar.Publish("timestamp", expvar.Func(func() interface{} {
		return time.Now().Unix()
	}))

	rdb, err := connectRedis(cfg)
	if err != nil {
		logger.PrintFatal(err, nil)
	}
	defer rdb.Close()

	logger.PrintInfo("redis connection pool established", nil)

	app := &application{
		config: cfg,
		logger: logger,
		mailer: mailer.New(cfg.smtp.host, cfg.smtp.port, cfg.smtp.username, cfg.smtp.password, cfg.smtp.sender, cfg.smtp.enabled),
		models: data.NewModels(db),
		redis:  rdb,
	}

	err = app.serve()
	if err != nil {
		logger.PrintFatal(err, nil)
	}
}

func openDB(cfg config) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.db.dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(cfg.db.maxOpenConns)
	db.SetMaxIdleConns(cfg.db.maxIdleConns)
	duration, err := time.ParseDuration(cfg.db.maxIdleTime)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxIdleTime(duration)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = db.PingContext(ctx)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func connectRedis(cfg config) (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "654321",
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return nil, err
	}

	return rdb, nil
}
