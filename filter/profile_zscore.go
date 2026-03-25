package filter

import (
	"math"
	"sync"
	"time"
)

type ResultadoZScore struct {
	PPSActual     float64
	MediaPPS      float64
	DesvioPPS     float64
	UmbralPPS     float64
	PuntajeZ      float64
	Alerta        bool
	Muestras      int
	UltimaMuestra time.Time
}

type PerfilZScore struct {
	mu               sync.Mutex
	inicioVentana    time.Time
	acumuladoVentana float64
	minMuestras      int
	umbralZ          float64
	minPPS           float64
	media            float64
	m2               float64
	cantidad         int
	ultimaMuestra    time.Time
}

func NuevoPerfilZScore(minMuestras int, umbralZ, minPPS float64) *PerfilZScore {
	return &PerfilZScore{
		minMuestras: minMuestras,
		umbralZ:     umbralZ,
		minPPS:      minPPS,
	}
}

func (p *PerfilZScore) Observar(ahora time.Time) ResultadoZScore {
	return p.ObservarConPeso(ahora, 1)
}

func (p *PerfilZScore) ObservarConPeso(ahora time.Time, peso float64) ResultadoZScore {
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
		return p.resultadoInterno(p.acumuladoVentana, false)
	}

	tasaActual := p.acumuladoVentana / transcurrido
	resultado := p.resultadoInterno(tasaActual, true)

	if transcurrido >= 1 {
		p.agregarMuestraInterna(tasaActual, ahora)
		p.inicioVentana = ahora
		p.acumuladoVentana = 0
		resultado = p.resultadoInterno(tasaActual, true)
	}

	return resultado
}

func (p *PerfilZScore) Resumen() ResultadoZScore {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resultadoInterno(0, false)
}

func (p *PerfilZScore) resultadoInterno(ppsActual float64, evaluar bool) ResultadoZScore {
	desvio := p.desvioInterno()
	umbralPPS := p.media + (p.umbralZ * desvio)
	puntajeZ := 0.0
	if desvio > 0 {
		puntajeZ = (ppsActual - p.media) / desvio
	}

	alerta := false
	if evaluar && p.cantidad >= p.minMuestras && ppsActual >= p.minPPS {
		if desvio == 0 {
			alerta = ppsActual > p.media && p.media > 0
		} else {
			alerta = puntajeZ >= p.umbralZ
		}
	}

	return ResultadoZScore{
		PPSActual:     ppsActual,
		MediaPPS:      p.media,
		DesvioPPS:     desvio,
		UmbralPPS:     umbralPPS,
		PuntajeZ:      puntajeZ,
		Alerta:        alerta,
		Muestras:      p.cantidad,
		UltimaMuestra: p.ultimaMuestra,
	}
}

func (p *PerfilZScore) agregarMuestraInterna(valor float64, momento time.Time) {
	p.cantidad++
	delta := valor - p.media
	p.media += delta / float64(p.cantidad)
	delta2 := valor - p.media
	p.m2 += delta * delta2
	p.ultimaMuestra = momento
}

func (p *PerfilZScore) desvioInterno() float64 {
	if p.cantidad < 2 {
		return 0
	}
	varianza := p.m2 / float64(p.cantidad-1)
	if varianza < 0 {
		return 0
	}
	return math.Sqrt(varianza)
}

type SnapshotPerfilZScore struct {
	Media         float64 `json:"media"`
	M2            float64 `json:"m2"`
	Cantidad      int     `json:"cantidad"`
	UltimaMuestra int64   `json:"ultima_muestra"`
}

func (p *PerfilZScore) Exportar() SnapshotPerfilZScore {
	p.mu.Lock()
	defer p.mu.Unlock()
	return SnapshotPerfilZScore{
		Media:         p.media,
		M2:            p.m2,
		Cantidad:      p.cantidad,
		UltimaMuestra: p.ultimaMuestra.Unix(),
	}
}

func (p *PerfilZScore) Importar(snapshot SnapshotPerfilZScore) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.media = snapshot.Media
	p.m2 = snapshot.M2
	p.cantidad = snapshot.Cantidad
	if snapshot.UltimaMuestra > 0 {
		p.ultimaMuestra = time.Unix(snapshot.UltimaMuestra, 0)
	}
}
