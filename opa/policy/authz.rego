package authz

# ---------------------------------------------------------------
# 1. Configuração (vem das variáveis de ambiente do container OPA)
# ---------------------------------------------------------------
config := {
	"tenant_id": opa.runtime().env.AZURE_TENANT_ID,
	"audience": opa.runtime().env.AZURE_AUDIENCE,
}

# Emissores aceitos: token v2.0 e token v1.0 do Microsoft Entra ID
emissores_validos := {
	sprintf("https://login.microsoftonline.com/%s/v2.0", [config.tenant_id]),
	sprintf("https://sts.windows.net/%s/", [config.tenant_id]),
}

# ---------------------------------------------------------------
# 2. Chaves públicas da Microsoft (JWKS) - cache de 1h
# ---------------------------------------------------------------
jwks := http.send({
	"method": "GET",
	"url": sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", [config.tenant_id]),
	"force_cache": true,
	"force_cache_duration_seconds": 3600,
}).raw_body

# ---------------------------------------------------------------
# 3. Extrai o token do header "Authorization: Bearer <token>"
# ---------------------------------------------------------------
token := t if {
	startswith(input.authorization, "Bearer ")
	t := substring(input.authorization, count("Bearer "), -1)
}

# ---------------------------------------------------------------
# 4. Valida assinatura, expiração e audience do token
# ---------------------------------------------------------------
claims := payload if {
	[valido, _, payload] := io.jwt.decode_verify(token, {
		"cert": jwks,
		"aud": config.audience,
	})
	valido
	payload.iss in emissores_validos
}

token_valido if claims

# ---------------------------------------------------------------
# 5. Regras de autorização
# ---------------------------------------------------------------
default allow := false

# Qualquer usuário autenticado pode LER produtos
allow if {
	token_valido
	input.method == "GET"
	input.path == "/produtos"
}

# Apenas quem tem a role "Produtos.Escrever" pode CRIAR produtos
allow if {
	token_valido
	input.method == "POST"
	input.path == "/produtos"
	"Produtos.Escrever" in claims.roles
}

# ---------------------------------------------------------------
# 6. Motivo da negação (ajuda a debugar e a explicar no treinamento)
# ---------------------------------------------------------------
motivo := "token ausente ou sem prefixo Bearer" if not token

else := "token inválido (assinatura, expiração, audience ou emissor)" if not token_valido

else := "usuário sem permissão para esta operação" if not allow

else := "permitido"

usuario := claims.preferred_username if token_valido
