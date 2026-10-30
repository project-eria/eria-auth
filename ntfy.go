package main

import (
	"net/http"
	"strings"
	"time"

	zlog "github.com/rs/zerolog/log"
)

// ntfy returns the alert sender (§4.5): a fixed title per event type, a
// terminal named by its record, never text coming from a Thing. Empty URL:
// alerts are only logged.
func ntfy(url string) func(title string) {
	client := &http.Client{Timeout: 10 * time.Second}
	return func(title string) {
		zlog.Warn().Str("alert", title).Msg("[ntfy]")
		if url == "" {
			return
		}
		go func() {
			req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(title))
			req.Header.Set("Title", "ERIA auth")
			resp, err := client.Do(req)
			if err != nil {
				zlog.Error().Err(err).Msg("[ntfy] not sent")
				return
			}
			resp.Body.Close()
		}()
	}
}
