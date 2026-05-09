package route

import (
	"github.com/metacubex/mihomo/listener"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func mitmRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/ca.crt", getMitmCA)
	return r
}

// getMitmCA serves the active MITM CA certificate as application/x-x509-ca-cert.
// Returns 404 when MITM is disabled or has not been initialised.
func getMitmCA(w http.ResponseWriter, r *http.Request) {
	pemBytes := listener.MitmCACert()
	if len(pemBytes) == 0 {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("MITM is disabled or CA not initialised"))
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="mitm.crt"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pemBytes)
}
