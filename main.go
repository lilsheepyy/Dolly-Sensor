package main

import (
	"dolly-sensor/app"
	"log"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
