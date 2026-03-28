package analyzer

import (
	"testing"
	"time"
)

func TestZScoreMath(t *testing.T) {
	p := NuevoPerfilZScore()
	ahora := time.Now()

	// Simular muestras cada 2 segundos para asegurar que la ventana se limpie
	for i := 1; i <= 5; i++ {
		_ = p.ObservarConPeso(ahora.Add(time.Duration(i*2)*time.Second), 2000)
	}
	
	res := p.Resumen()
	if res.Media < 500 {
		t.Errorf("La media debería estar convergiendo, actual: %f", res.Media)
	}

	// Un pico claro: enviamos 100000 unidades en 2 segundos = 50000 PPS
	pico := p.ObservarConPeso(ahora.Add(12*time.Second), 100000)
	
	if pico.Actual < 45000 {
		t.Errorf("El valor actual debería estar cerca de 50000, obtenido: %f", pico.Actual)
	}
	
	if pico.Desvio == 0 {
		t.Error("El desvío estándar debería ser mayor a 0 tras un pico")
	}
}
