package perfilglobal

import (
	"math"
	"sync"
	"time"
)

type ResultadoZ struct {
	Actual        float64
	Promedio      float64
	Desvio        float64
	Muestras      int
	UltimaMuestra time.Time
}

type PerfilZ struct {
	mu               sync.Mutex
	inicioVentana    time.Time
	acumuladoVentana float64
	promedio         float64
	m2               float64
	muestras         int
	ultimaMuestra    time.Time
}

func NuevoPerfilZ() *PerfilZ {
	return &PerfilZ{}
}

func (p *PerfilZ) Observar(ahora time.Time, peso float64) ResultadoZ {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.inicioVentana.IsZero() {
		p.inicioVentana = ahora
	}
	if peso <= 0 {
		peso = 1
	}

	p.acumuladoVentana += peso
	transcurrido := ahora.Sub(p.inicioVentana).Seconds()
	if transcurrido <= 0 {
		return p.resultadoInterno(0)
	}

	tasaActual := p.acumuladoVentana / transcurrido
	if transcurrido >= 1 {
		p.agregarMuestraInterna(tasaActual, ahora)
		p.inicioVentana = ahora
		p.acumuladoVentana = 0
	}

	return p.resultadoInterno(tasaActual)
}

func (p *PerfilZ) Resumen() ResultadoZ {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resultadoInterno(0)
}

func (p *PerfilZ) resultadoInterno(actual float64) ResultadoZ {
	return ResultadoZ{
		Actual:        actual,
		Promedio:      p.promedio,
		Desvio:        p.desvioInterno(),
		Muestras:      p.muestras,
		UltimaMuestra: p.ultimaMuestra,
	}
}

func (p *PerfilZ) agregarMuestraInterna(valor float64, momento time.Time) {
	p.muestras++
	delta := valor - p.promedio
	p.promedio += delta / float64(p.muestras)
	delta2 := valor - p.promedio
	p.m2 += delta * delta2
	p.ultimaMuestra = momento
}

func (p *PerfilZ) desvioInterno() float64 {
	if p.muestras < 2 {
		return 0
	}
	varianza := p.m2 / float64(p.muestras-1)
	if varianza < 0 {
		return 0
	}
	return math.Sqrt(varianza)
}
