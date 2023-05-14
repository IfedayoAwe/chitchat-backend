package main

import (
	"expvar"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/tomasen/realip"
	"golang.org/x/time/rate"
)

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Connection", "close")
				app.serverErrorResponse(w, r, fmt.Errorf("%s", err))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (app *application) rateLimit(next http.Handler) http.Handler {
	type client struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}
	var (
		mu      sync.Mutex
		clients = make(map[string]*client)
	)

	go func() {
		for {
			time.Sleep(time.Minute)

			mu.Lock()

			for ip, client := range clients {
				if time.Since(client.lastSeen) > 3*time.Minute {
					delete(clients, ip)
				}
			}

			mu.Unlock()
		}
	}()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if app.config.limiter.enabled {
			ip := realip.FromRequest(r)
			mu.Lock()
			if _, found := clients[ip]; !found {
				clients[ip] = &client{
					limiter: rate.NewLimiter(rate.Limit(app.config.limiter.rps), app.config.limiter.burst),
				}
			}
			clients[ip].lastSeen = time.Now()
			if !clients[ip].limiter.Allow() {
				mu.Unlock()
				app.rateLimitExceededResponse(w, r)
				return
			}
			mu.Unlock()
		}
		next.ServeHTTP(w, r)
	})
}

// func (app *application) validateOTP(scope string, next http.HandlerFunc) http.HandlerFunc {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		w.Header().Add("Vary", "Authorization")
// 		authorizationHeader := r.Header.Get("Authorization")
// 		if authorizationHeader == "" {
// 			app.invalidAuthenticationTokenResponse(w, r)
// 			return
// 		}
// 		headerParts := strings.Split(authorizationHeader, " ")
// 		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
// 			app.invalidAuthenticationTokenResponse(w, r)
// 			return
// 		}
// 		token := headerParts[1]

// 		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(token)

// 		if err != nil {
// 			app.invalidAuthenticationTokenResponse(w, r)
// 			return
// 		}

// 		otpScope, otpCode, err := app.splitScopeAndCode(string(decoded))
// 		if err != nil {
// 			app.invalidAuthenticationTokenResponse(w, r)
// 			return
// 		}

// 		if otpScope != scope {
// 			app.invalidAuthenticationTokenResponse(w, r)
// 			return
// 		}

// 		now := time.Now().UTC()
// 		valid, err := totp.ValidateCustom(otpCode, app.config.jwt.secret, now, totp.ValidateOpts{
// 			Period: app.config.otp.period,
// 			Digits: 6,
// 		})

// 		if err != nil {
// 			fmt.Println(err)
// 			return
// 		}

// 		if !valid {
// 			app.invalidAuthenticationTokenResponse(w, r)
// 			return
// 		}

// 		next.ServeHTTP(w, r)
// 	})
// }

// func (app *application) requireAuthenticatedUser(next http.HandlerFunc) http.HandlerFunc {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		user := app.contextGetUser(r)
// 		if user.IsAnonymous() {
// 			app.authenticationRequiredResponse(w, r)
// 			return
// 		}
// 		next.ServeHTTP(w, r)
// 	})
// }

// func (app *application) requireActivatedUser(next http.HandlerFunc) http.HandlerFunc {
// 	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

// 		user := app.contextGetUser(r)
// 		if !user.Activated {
// 			app.inactiveAccountResponse(w, r)
// 			return
// 		}
// 		next.ServeHTTP(w, r)
// 	})
// 	return app.requireAuthenticatedUser(fn)
// }

func (app *application) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Vary", "Access-Control-Request-Method")
		origin := r.Header.Get("Origin")
		if origin != "" && len(app.config.cors.trustedOrigins) != 0 {
			for i := range app.config.cors.trustedOrigins {
				if origin == app.config.cors.trustedOrigins[i] {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					// perflight request
					if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
						w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, PUT, PATCH, DELETE")
						w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
						w.WriteHeader(http.StatusOK)
						return
					}

				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (app *application) metrics(next http.Handler) http.Handler {
	if app.config.metrics.enabled {
		totalRequestsReceived := expvar.NewInt("total_requests_received")
		totalResponsesSent := expvar.NewInt("total_responses_sent")
		totalProcessingTimeMicroseconds := expvar.NewInt("total_processing_time_μs")
		totalProcessingTimeMicrosecondsByMetrics := expvar.NewInt("total_processing_metrics_time_μs")
		totalResponsesSentByStatus := expvar.NewMap("total_responses_sent_by_status")

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			totalRequestsReceived.Add(1)
			metrics := httpsnoop.CaptureMetrics(next, w, r)
			totalResponsesSent.Add(1)
			duration := time.Since(start).Microseconds()
			totalProcessingTimeMicroseconds.Add(duration)
			totalProcessingTimeMicrosecondsByMetrics.Add(metrics.Duration.Microseconds())
			totalResponsesSentByStatus.Add(strconv.Itoa(metrics.Code), 1)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})

}
