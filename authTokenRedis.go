package main

import (
	"fmt"
	"github.com/garyburd/redigo/redis"
	"log"
	"os"
	"time"
	"github.com/satori/go.uuid"
	"encoding/json"
	"encoding/base64"
	"strconv"
	"crypto/sha256"
)

var redisPool *redis.Pool
var maxConnections = 10
var maxIdleConnections = 2

var expireDuration = time.Hour * 1

var editorKey = "editor"
var tokensKey = "tokens"

func createJSONOutput(user string, authToken string, status int) string {
	outputMap := make(map[string]string)

	outputMap["status"] = strconv.Itoa(status)
	outputMap["user"] = user
	outputMap["authToken"] = authToken

	output, err := json.Marshal(outputMap)
	if err != nil {
		log.Println(err.Error())
		return err.Error()
	}
	return string(output)
}

func generateUUID() string {
	return uuid.NewV4().String()
}

func generateDigestAndEncode(authToken string) string {
	//Generate SHA256 digest
	sum := sha256.Sum256([]byte(authToken))
	//Base64 encode digest to handle as string
	encodedSum := base64.StdEncoding.EncodeToString(sum[:])

	return encodedSum;
}

func addKeyValue(key string, value string) int {
	c := redisPool.Get()
	defer c.Close()

	_, err := redis.Int(c.Do("SADD", key, value))
	if err != nil {
		log.Printf("SADD error: %v", err.Error())
		return -1
	}

	return 0
}

func remKeyValue(key string, value string) {
	c := redisPool.Get()
	defer c.Close()

	_, err := redis.Int(c.Do("SREM", key, value))
	if err != nil {
		log.Printf("SISMEMBER error: %v", err.Error())
	}
}

func setKeyExpiration(key string, expire time.Duration) int {
	c := redisPool.Get()
	defer c.Close()

	_, err := redis.Int(c.Do("EXPIRE", key, int(expire.Seconds())))
	if err != nil {
		fmt.Printf("EXPIRE error: %v\n", err.Error())
		return -1
	}
	return 0
}

func checkKeyValueIsMember(key string, value string) bool {
	c := redisPool.Get()
	defer c.Close()

	setResult, err := redis.Int(c.Do("SISMEMBER", key, value))
	if err != nil {
		log.Printf("SISMEMBER error: %v", err.Error())
		return false
	}

	if setResult == 1 {
		return true
	} else {
		return false
	}
}

func removeAllAuthTokensForUser(user string) {
	c:= redisPool.Get()
	defer c.Close()

	userTokenKey := fmt.Sprintf("%v:%v:%v", editorKey, user, tokensKey)

	_, err := redis.Int(c.Do("DEL", userTokenKey));
	if err != nil {
		log.Printf("DEL error: %v", err.Error())
	}
}

func checkAuthTokenForUser(user string, authToken string) bool {
	userTokenKey := fmt.Sprintf("%v:%v:%v", editorKey, user, tokensKey)

	return checkKeyValueIsMember(userTokenKey, generateDigestAndEncode(authToken))
}

func setAuthTokenForUser(user string) string {
	c := redisPool.Get()
	defer c.Close()

	userTokenKey := fmt.Sprintf("%v:%v:%v", editorKey, user, tokensKey)

	authToken := generateUUID()

	if addKeyValue(userTokenKey, generateDigestAndEncode(authToken)) == 0 && setKeyExpiration(userTokenKey, expireDuration) == 0 {
		return authToken
	}

	remKeyValue(userTokenKey, authToken)

	return ""
}

func refreshAuthTokenForUser(user string, oldAuthToken string) string {
	if (checkAuthTokenForUser(user, oldAuthToken) == true) {
		remKeyValue(user, oldAuthToken);
		return setAuthTokenForUser(user);
	}

	return ""
}

func createRedisPool() *redis.Pool {
	pool := redis.NewPool(func() (redis.Conn, error) {
		c, err := redis.DialURL(os.Getenv("REDIS_URL"))

		if err != nil {
			log.Println(err)
			return nil, err
		}

		return c, err
	}, maxIdleConnections)
	pool.TestOnBorrow = func(c redis.Conn, t time.Time) error {
        if time.Since(t) < time.Minute {
            return nil
        }
        _, err := c.Do("PING")
        return err
    }

	pool.MaxActive = maxConnections
	pool.IdleTimeout = time.Second * 10
	return pool
}
