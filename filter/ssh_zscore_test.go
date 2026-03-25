package filter

import (
	"math"
	"testing"
	"time"
)

func TestPerfilZScoreNoAlertaDuranteWarmup(t *testing.T) {
	perfil := NuevoPerfilZScore(5, 3.0, 10)
	inicio := time.Unix(1_700_000_000, 0)

	for i := 0; i < 4; i++ {
		perfil.Observar(inicio.Add(time.Duration(i) * time.Second))
		perfil.Observar(inicio.Add(time.Duration(i)*time.Second + 500*time.Millisecond))
	}

	resultado := perfil.Observar(inicio.Add(5*time.Second + 500*time.Millisecond))
	if resultado.Alerta {
		t.Fatalf("did not expect alert during warmup")
	}
}

func TestPerfilZScoreAlertaConAnomalia(t *testing.T) {
	perfil := NuevoPerfilZScore(5, 2.5, 5)
	inicio := time.Unix(1_700_000_000, 0)

	for i := 0; i < 12; i++ {
		t0 := inicio.Add(time.Duration(i) * time.Second)
		for n := 0; n < 10; n++ {
			_ = perfil.Observar(t0.Add(time.Duration(n) * 100 * time.Millisecond))
		}
	}

	t0 := inicio.Add(13 * time.Second)
	var resultado ResultadoZScore
	for n := 0; n < 40; n++ {
		resultado = perfil.Observar(t0.Add(time.Duration(n) * 20 * time.Millisecond))
	}

	if !resultado.Alerta {
		t.Fatalf("expected anomaly alert, got none (z=%.2f mean=%.2f std=%.2f)", resultado.PuntajeZ, resultado.MediaPPS, resultado.DesvioPPS)
	}
	if resultado.PuntajeZ <= 0 {
		t.Fatalf("expected positive z-score, got %.2f", resultado.PuntajeZ)
	}
}

func TestPerfilZScoreExportarImportar(t *testing.T) {
	perfil := NuevoPerfilZScore(3, 3.0, 1)
	inicio := time.Unix(1_700_000_000, 0)

	for i := 0; i < 10; i++ {
		_ = perfil.Observar(inicio.Add(time.Duration(i) * time.Second))
		_ = perfil.Observar(inicio.Add(time.Duration(i)*time.Second + 300*time.Millisecond))
	}

	snapshot := perfil.Exportar()
	clonado := NuevoPerfilZScore(3, 3.0, 1)
	clonado.Importar(snapshot)

	r1 := perfil.Resumen()
	r2 := clonado.Resumen()

	if r1.Muestras != r2.Muestras {
		t.Fatalf("expected same sample count, got %d and %d", r1.Muestras, r2.Muestras)
	}
	if math.Abs(r1.MediaPPS-r2.MediaPPS) > 1e-9 {
		t.Fatalf("expected same mean, got %.10f and %.10f", r1.MediaPPS, r2.MediaPPS)
	}
	if math.Abs(r1.DesvioPPS-r2.DesvioPPS) > 1e-9 {
		t.Fatalf("expected same std deviation, got %.10f and %.10f", r1.DesvioPPS, r2.DesvioPPS)
	}
}
