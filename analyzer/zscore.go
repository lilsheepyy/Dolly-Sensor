package analyzer

import (
	"math"
	"sync"
	"time"
)

type ResultadoZScore struct {
	Actual   float64
	Media    float64
	Desvio   float64
	Muestras int
}

type PerfilZScore struct {
	mu               sync.Mutex
	inicioVentana    time.Time
	acumuladoVentana float64
	media            float64
	m2               float64
	cantidad         int
	ultimaMuestra    time.Time
}

const alphaAdaptacion = 0.1

func NuevoPerfilZScore() *PerfilZScore {
	return &PerfilZScore{}
}

func (p *PerfilZScore) ObservarConPeso(ahora time.Time, peso float64) ResultadoZScore {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.inicioVentana.IsZero() {
		p.inicioVentana = ahora
	}
	p.acumuladoVentana += peso

	transcurrido := ahora.Sub(p.inicioVentana).Seconds()
	if transcurrido >= 1.0 {
		tasa := p.acumuladoVentana / transcurrido
		p.actualizarEstadisticas(tasa, ahora)
		p.inicioVentana = ahora
		p.acumuladoVentana = 0
		return p.resultadoInterno(tasa)
	}

	return p.resultadoInterno(0)
}

func (p *PerfilZScore) Resumen() ResultadoZScore {
	p.mu.Lock()
	defer p.mu.Unlock()
	tasa := 0.0
	if !p.inicioVentana.IsZero() {
		if dur := time.Since(p.inicioVentana).Seconds(); dur > 0 {
			tasa = p.acumuladoVentana / dur
		}
	}
	return p.resultadoInterno(tasa)
}

func (p *PerfilZScore) resultadoInterno(actual float64) ResultadoZScore {
	varianza := 0.0
	if p.cantidad > 1 {
		varianza = p.m2 / float64(p.cantidad-1)
	}
	desvio := math.Sqrt(varianza)
	return ResultadoZScore{
		Actual: actual, Media: p.media, Desvio: desvio, Muestras: p.cantidad,
	}
}

func (p *PerfilZScore) actualizarEstadisticas(valor float64, momento time.Time) {
	p.cantidad++
	if p.cantidad == 1 {
		p.media = valor
		p.m2 = 0
	} else {
		// Usamos un factor de olvido para que el baseline no sea infinito
		// pero mantenemos el cálculo de varianza
		diff := valor - p.media
		p.media += alphaAdaptacion * diff
		p.m2 = (1-alphaAdaptacion)*p.m2 + alphaAdaptacion*diff*(valor-p.media)
	}
	p.ultimaMuestra = momento
}
