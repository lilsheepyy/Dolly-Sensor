package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	target := "80.31.128.178:8080"
	fmt.Printf("🚀 Iniciando conexión hacia %s...\n", target)

	// 1. Realizar Handshake TCP
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		fmt.Printf("❌ Error al conectar: %v\n", err)
		return
	}
	
	fmt.Println("✅ Handshake completado. Conexión establecida.")
	fmt.Println("⏳ Manteniendo conexión abierta durante 60 segundos...")
	fmt.Println("👀 Deberías ver esta conexión en la pestaña 'Connections' de Dolly-Sensor.")

	// 2. Mantener abierta por 60s
	time.Sleep(60 * time.Second)

	// 3. Cerrar conexión
	conn.Close()
	fmt.Println("🛑 Conexión cerrada tras 60 segundos.")
}
