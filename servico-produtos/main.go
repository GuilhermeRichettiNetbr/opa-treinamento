package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

var opaURL = getEnv("OPA_URL", "http://localhost:8181") + "/v1/data/authz"

type decisaoOPA struct {
	Result struct {
		Allow   bool   `json:"allow"`
		Motivo  string `json:"motivo"`
		Usuario string `json:"usuario"`
	} `json:"result"`
}

// Middleware que pergunta ao OPA se a requisição pode seguir.
func autorizar(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entrada, _ := json.Marshal(map[string]any{
			"input": map[string]string{
				"method":        r.Method,
				"path":          r.URL.Path,
				"authorization": r.Header.Get("Authorization"),
			},
		})

		resp, err := http.Post(opaURL, "application/json", bytes.NewReader(entrada))
		if err != nil {
			http.Error(w, "OPA indisponível", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		var decisao decisaoOPA
		if err := json.NewDecoder(resp.Body).Decode(&decisao); err != nil {
			http.Error(w, "resposta inválida do OPA", http.StatusInternalServerError)
			return
		}

		log.Printf("%s %s -> allow=%v motivo=%q usuario=%q",
			r.Method, r.URL.Path, decisao.Result.Allow, decisao.Result.Motivo, decisao.Result.Usuario)

		if !decisao.Result.Allow {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"erro": decisao.Result.Motivo})
			return
		}
		next(w, r)
	}
}

var produtos = []string{"Notebook", "Mouse", "Teclado"}

func listarProdutos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(produtos)
}

func criarProduto(w http.ResponseWriter, r *http.Request) {
	var novo struct {
		Nome string `json:"nome"`
	}
	if err := json.NewDecoder(r.Body).Decode(&novo); err != nil || novo.Nome == "" {
		http.Error(w, `envie {"nome": "..."}`, http.StatusBadRequest)
		return
	}
	produtos = append(produtos, novo.Nome)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(produtos)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /produtos", autorizar(listarProdutos))
	mux.HandleFunc("POST /produtos", autorizar(criarProduto))

	porta := getEnv("PORT", "8080")
	log.Println("servico-produtos ouvindo em :"+porta+", OPA em", opaURL)
	log.Fatal(http.ListenAndServe(":"+porta, mux))
}

func getEnv(chave, padrao string) string {
	if v := os.Getenv(chave); v != "" {
		return v
	}
	return padrao
}
