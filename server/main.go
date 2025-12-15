// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 mochi-mqtt, mochi-co
// SPDX-FileContributor: mochi-co

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/listeners"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
)

func main() {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()

	server := mqtt.New(&mqtt.Options{
		InlineClient: true, // you must enable inline client to use direct publishing and subscribing.
	})
	_ = server.AddHook(new(auth.AllowHook), nil)

	tcp := listeners.NewTCP(listeners.Config{ID: "t1", Address: ":1883"})
	err := server.AddListener(tcp)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		// Subscribe to a filter and handle any received messages via a callback function.
		callbackFn := func(cl *mqtt.Client, sub packets.Subscription, pk packets.Packet) {
			log.Printf("Message received: %s\n", string(pk.Payload))
		}
		server.Log.Info("inline client subscribing")
		_ = server.Subscribe("main/#", 1, callbackFn)
	}()

	// Start the server
	go func() {
		err := server.Serve()
		if err != nil {
			log.Fatal(err)
		}
	}()

	// go func() {
	// 	time.Sleep(time.Second * 10)
	// 	// Unsubscribe from the same filter to stop receiving messages.
	// 	server.Log.Info("inline client unsubscribing")
	// 	_ = server.Unsubscribe("direct/#", 1)
	// }()

	<-done
	server.Log.Warn("caught signal, stopping...")
	_ = server.Close()
	server.Log.Info("main.go finished")
}
