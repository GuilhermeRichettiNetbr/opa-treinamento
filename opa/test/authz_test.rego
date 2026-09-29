package authz_test

import data.authz

# Chave RSA gerada só para os testes (simula a chave da Microsoft).
# NÃO é segredo: serve apenas para assinar tokens falsos localmente.
chave_privada := {"alg": "RS256", "d": "AT8xrX8paHkjO-xavny5pjUesizZmO0JD-tnP9d_4BjTifb3K0nvJryMupzuhxqNL2ykL3KYMsemIE9_BtrvJtj0Yui3M7-QOTNnhS5njpZQEBsIefmCixrEzsO10hOLnTlULtp7Q7UGQA2VnaEjg2hwE3OSUhV3HnQRgzb56bboLOjlP96KH6wPEWFFQS-kcWu56DRPwT2NwV5YTC5uRaCFTjqUbutjMLtNlmboJbBNB6UwPPBAJhr52Cs0fNHrJb3sNJVlBMgVtNrNPLGddT7qJw37w4N1iKx198E1BqZKTzBlZNZLQK1CBtIZuFfK9nYbZOAp8miJObmOhESlIQ", "dp": "PkNHFuWxA3Jkd_D9ud4ge34YGKBft1sxH5zifYWdnCzuOV07FqLlDqIEBOZn72z9SP9aJDCxgMAVAwEsI8-beS2C8xUHkPIhKSFwmwaKOIRsxzGEihWhVXCI28goDZfjVTIz4Zw2IQMbrkxs7XC7EHVtxClOm43lVsvWV_wcDjE", "dq": "Q0aDD6F2Y_Qw9tQgx24p2xbDimWzx4_gEIAM_6RUuGqPBjS8jGBOJAAbKm_TzHydv87oKp40CZNJcmY40ol0KA265Dz-ko5LkQ3P2-C6OJIVHkx3D8IyJfs8hfWrhnS5bNJ5EXkKKA-AnzlPpm8qlUIoNeXWGkwAGx4nH8XW7gE", "e": "AQAB", "kid": "chave-teste", "kty": "RSA", "n": "1DpqLMAWGN_p1WVZljKTvEApuphfJm32fAVjExejAOM8E6lBhsuGBRNvkFdH_Ej5W3uQGALHW4puecawsS-hy_0Y158Adq4Lz52LrmRETK9ALEGLhMRZrfCmQ385uYAX6kl-6dBXF2V0P_v3w8axnqx7D8oJp8iYbK1J7FWWkQIJM-1iTsDkqj6nxmVDJm7JhANeLo988v-Pb4I40Rg8dtm14vF9IPKyGKfUYM9DrJ7szfsph5G6SczSDBSLHpovk_i14FwQn5t6q8Nz0iAWCS3jJfiHoM3qMFlPyn52TcJt440GTca7rpk18-tIjwHeZiUZzbHPNvXkYfuDIHWiRQ", "p": "59xaKQ-bWzYJx6s_n5XJxBPksUwCYbS-mNo5jQ6MVuhH5FqotLGTmCBF7DkmYpuvRJhQ7ckggLqCStQo3Dod1M_W0EX6H3lGHep3uQBwofe6OwEHZfUU8pnYhqe3WivqBZQ6THxWexvO2qHUpm7-1swsxHpJh4j3WuNCMpHIjdE", "q": "6lLOqyngugx5noukE1wZYKlXhqgHlPKbbwWgNqhU2oxKrVSAA-AkoUhCwXSoARgVuFXgkKGBaXXPUMHk6IVQyEw7BR01U8RUBLLzgYgjLJNXu6r1EHPV4UVCMXHe294KCN6Oa8il5HwzI54-QUo-wQtJCOYKc2cbhoHFobM_ZjU", "qi": "RIOlKkaDxnOfakkqkD4mi0Kao9bn35AjYdpwkF7I5ypBE0b8oqnB1R4IEZFYVVDyi7P0eKCy7M2x0Df9LiwGJRcKZvlc3VrR7Ung_RGHsp5zPlpCz-BntawyPW_XpuIKLmWlVIrEyBi1wwxyHaXz9X1KWfvK0apNMQoDfcRRLdw"}

jwks_teste := json.marshal({"keys": [object.remove(chave_privada, ["d", "p", "q", "dp", "dq", "qi"])]})

config_teste := {"tenant_id": "meu-tenant", "audience": "api://produtos"}

# Monta um token parecido com o da Microsoft, sobrescrevendo campos quando necessário
gerar_token(extra) := io.jwt.encode_sign(
	{"alg": "RS256", "typ": "JWT", "kid": "chave-teste"},
	object.union(
		{
			"iss": "https://login.microsoftonline.com/meu-tenant/v2.0",
			"aud": "api://produtos",
			"exp": (time.now_ns() / 1000000000) + 3600,
			"preferred_username": "ana@empresa.com",
			"roles": [],
		},
		extra,
	),
	chave_privada,
)

requisicao(method, token) := {
	"method": method,
	"path": "/produtos",
	"authorization": concat(" ", ["Bearer", token]),
}

test_get_com_token_valido_permite if {
	authz.allow with input as requisicao("GET", gerar_token({}))
		with authz.config as config_teste
		with authz.jwks as jwks_teste
}

test_sem_token_nega if {
	not authz.allow with input as {"method": "GET", "path": "/produtos"}
		with authz.config as config_teste
		with authz.jwks as jwks_teste
}

test_token_expirado_nega if {
	not authz.allow with input as requisicao("GET", gerar_token({"exp": 1000}))
		with authz.config as config_teste
		with authz.jwks as jwks_teste
}

test_audience_errada_nega if {
	not authz.allow with input as requisicao("GET", gerar_token({"aud": "api://outra-api"}))
		with authz.config as config_teste
		with authz.jwks as jwks_teste
}

test_emissor_de_outro_tenant_nega if {
	iss := "https://login.microsoftonline.com/tenant-hacker/v2.0"
	not authz.allow with input as requisicao("GET", gerar_token({"iss": iss}))
		with authz.config as config_teste
		with authz.jwks as jwks_teste
}

test_post_sem_role_nega if {
	not authz.allow with input as requisicao("POST", gerar_token({}))
		with authz.config as config_teste
		with authz.jwks as jwks_teste
}

test_post_com_role_permite if {
	authz.allow with input as requisicao("POST", gerar_token({"roles": ["Produtos.Escrever"]}))
		with authz.config as config_teste
		with authz.jwks as jwks_teste
}

test_motivo_sem_permissao if {
	authz.motivo == "usuário sem permissão para esta operação" with input as requisicao("POST", gerar_token({}))
		with authz.config as config_teste
		with authz.jwks as jwks_teste
}
