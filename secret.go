package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// PINs and the level 0 passphrase are hashed with argon2id over
// HMAC(pepper, secret): the pepper never enters the backup, so a stolen
// backup cannot be brute-forced offline (AUTH-DESIGN §3.3).
type Hasher struct {
	pepper []byte
}

func (h Hasher) hash(secret string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key := argon2.IDKey(h.peppered(secret), salt, 2, 19*1024, 1, 32)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s", b64.EncodeToString(salt), b64.EncodeToString(key))
}

func (h Hasher) check(secret, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey(h.peppered(secret), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func (h Hasher) peppered(secret string) []byte {
	mac := hmac.New(sha256.New, h.pepper)
	mac.Write([]byte(secret))
	return mac.Sum(nil)
}

var pinFormat = regexp.MustCompile(`^[0-9]{4}$`)

// Invalid is an error the API may explain to the user: a weak or malformed
// new secret. Any other error is answered without detail.
type Invalid string

func (e Invalid) Error() string { return string(e) }

// checkPIN refuses the weak PINs (AUTH-DESIGN §3.3): repetitions, sequences,
// years 1900-2030, DDMM dates and the most common ones.
func checkPIN(pin string) error {
	if !pinFormat.MatchString(pin) {
		return Invalid("the PIN has 4 digits")
	}
	weak := Invalid("this PIN is too easy to guess")
	d := []int{int(pin[0] - '0'), int(pin[1] - '0'), int(pin[2] - '0'), int(pin[3] - '0')}
	up, down, same := true, true, true
	for i := 1; i < 4; i++ {
		up = up && d[i] == (d[i-1]+1)%10
		down = down && d[i] == (d[i-1]+9)%10
		same = same && d[i] == d[i-1]
	}
	if up || down || same || (d[0] == d[2] && d[1] == d[3]) || (d[0] == d[1] && d[2] == d[3]) {
		return weak // 1234, 4321, 1111, 1212, 1122
	}
	n, _ := strconv.Atoi(pin)
	if n >= 1900 && n <= 2030 {
		return weak
	}
	if _, err := time.Parse("0201", pin); err == nil || pin == "2902" {
		return weak // DDMM, leap day included
	}
	switch pin {
	case "6969", "1004", "4200", "1313", "7777", "0007", "2580", "0852", "1590":
		return weak
	}
	return nil
}

// checkPassphrase bounds the level 0 passphrase.
func checkPassphrase(p string) error {
	if len([]rune(p)) < 12 || len(p) > 256 {
		return Invalid("the passphrase has 12 to 256 characters")
	}
	return nil
}

// randomCode returns n characters from an alphabet without look-alikes.
func randomCode(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
