package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/big"
	mrand "math/rand/v2"
	"sync"
	"time"
)

// A small hand-rolled 5x7 bitmap font for digits 0-9, so the login CAPTCHA
// needs no font/image dependency (same reasoning as auth.go's pbkdf2: avoid
// a new module requirement just for this). '#' = filled pixel.
var digitFont = map[byte][7]string{
	'0': {"#####", "#...#", "#...#", "#...#", "#...#", "#...#", "#####"},
	'1': {"..#..", ".##..", "..#..", "..#..", "..#..", "..#..", "#####"},
	'2': {"#####", "....#", "....#", "#####", "#....", "#....", "#####"},
	'3': {"#####", "....#", "....#", "#####", "....#", "....#", "#####"},
	'4': {"#...#", "#...#", "#...#", "#####", "....#", "....#", "....#"},
	'5': {"#####", "#....", "#....", "#####", "....#", "....#", "#####"},
	'6': {"#####", "#....", "#....", "#####", "#...#", "#...#", "#####"},
	'7': {"#####", "....#", "....#", "...#.", "..#..", ".#...", ".#..."},
	'8': {"#####", "#...#", "#...#", "#####", "#...#", "#...#", "#####"},
	'9': {"#####", "#...#", "#...#", "#####", "....#", "....#", "#####"},
}

const captchaTTL = 5 * time.Minute
const captchaDigits = 5

type captchaEntry struct {
	answer  string
	expires time.Time
}

// CaptchaStore issues short-lived, one-time-use numeric image challenges.
// This is a secondary speed bump on top of the real defense (AuthStore's
// per-account lockout) — it makes naive scripted credential-stuffing (which
// posts username/password with no HTML/image parsing at all) fail outright,
// without needing a third-party CAPTCHA service or network access.
type CaptchaStore struct {
	mu      sync.Mutex
	entries map[string]captchaEntry
}

func NewCaptchaStore() *CaptchaStore {
	return &CaptchaStore{entries: map[string]captchaEntry{}}
}

// New generates a random-digit challenge, returning (id, PNG data URI).
func (c *CaptchaStore) New() (string, string) {
	digits := make([]byte, captchaDigits)
	for i := range digits {
		n, _ := rand.Int(rand.Reader, big.NewInt(10))
		digits[i] = byte('0') + byte(n.Int64())
	}
	answer := string(digits)

	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)

	c.mu.Lock()
	c.entries[id] = captchaEntry{answer: answer, expires: time.Now().Add(captchaTTL)}
	now := time.Now()
	for k, v := range c.entries {
		if now.After(v.expires) {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()

	return id, renderCaptchaPNG(answer)
}

// Verify checks and consumes (one-time use, regardless of outcome) a
// challenge answer.
func (c *CaptchaStore) Verify(id, answer string) bool {
	c.mu.Lock()
	e, ok := c.entries[id]
	delete(c.entries, id)
	c.mu.Unlock()
	if !ok || time.Now().After(e.expires) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(e.answer), []byte(answer)) == 1
}

func renderCaptchaPNG(answer string) string {
	const cellW, cellH = 6, 6
	const glyphCols, glyphRows = 5, 7
	const gap = 10
	glyphW, glyphH := glyphCols*cellW, glyphRows*cellH
	const pad = 12
	width := pad*2 + len(answer)*glyphW + (len(answer)-1)*gap
	height := pad*2 + glyphH + 8

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{247, 247, 250, 255}}, image.Point{}, draw.Src)

	// Background noise dots — makes naive fixed-threshold OCR harder.
	for i := 0; i < width*height/10; i++ {
		x, y := mrand.IntN(width), mrand.IntN(height)
		img.Set(x, y, color.RGBA{
			uint8(180 + mrand.IntN(60)), uint8(180 + mrand.IntN(60)), uint8(180 + mrand.IntN(60)), 255})
	}
	// A few distortion lines through the whole image.
	for i := 0; i < 4; i++ {
		y0, y1 := mrand.IntN(height), mrand.IntN(height)
		col := color.RGBA{uint8(150 + mrand.IntN(80)), uint8(150 + mrand.IntN(80)), uint8(150 + mrand.IntN(80)), 255}
		for x := 0; x < width; x++ {
			y := y0 + (y1-y0)*x/max(width-1, 1)
			img.Set(x, y, col)
		}
	}

	x := pad
	for _, ch := range []byte(answer) {
		glyph := digitFont[ch]
		col := color.RGBA{uint8(20 + mrand.IntN(60)), uint8(20 + mrand.IntN(60)), uint8(90 + mrand.IntN(100)), 255}
		yOff := pad + mrand.IntN(7) - 3
		xOff := x + mrand.IntN(3) - 1
		for row := 0; row < glyphRows; row++ {
			for c := 0; c < glyphCols; c++ {
				if glyph[row][c] != '#' {
					continue
				}
				px0, py0 := xOff+c*cellW, yOff+row*cellH
				for dx := 0; dx < cellW; dx++ {
					for dy := 0; dy < cellH; dy++ {
						px, py := px0+dx, py0+dy
						if px >= 0 && px < width && py >= 0 && py < height {
							img.Set(px, py, col)
						}
					}
				}
			}
		}
		x += glyphW + gap
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}
