# opa-treinamento

Treinamento de OPA (Open Policy Agent): validando tokens Microsoft Entra ID.

```
 cliente ──(Bearer token)──> servico-produtos (Go :8080) ──(input)──> OPA (:8181)
                                     │                                   │
                                     │<──── {allow, motivo, usuario} ────┘
                                                                         │
                                         JWKS da Microsoft <──(http.send)┘
```

O serviço Go **não sabe nada sobre JWT**. Ele só pergunta ao OPA: "posso deixar essa requisição passar?".
A política (`opa/policy/authz.rego`) é copiada **para dentro da imagem do OPA** (`opa/Dockerfile`).

## Estrutura

| Arquivo | O que é |
|---|---|
| `opa/policy/authz.rego` | A política: valida o token e decide quem acessa o quê |
| `opa/test/authz_test.rego` | Testes da política (rodam sem Azure, com uma chave falsa) |
| `opa/Dockerfile` | Imagem do OPA com a política embutida |
| `servico-produtos/main.go` | Microsserviço Go com o middleware que consulta o OPA |
| `docker-compose.yml` | Sobe os dois containers |

## O que a política verifica

1. O header `Authorization: Bearer <token>` existe
2. A **assinatura** do token bate com as chaves públicas da Microsoft (JWKS do tenant)
3. O token **não expirou**
4. O **audience** (`aud`) é a sua API
5. O **emissor** (`iss`) é o seu tenant (aceita tokens v1.0 e v2.0)
6. Regras de negócio:
   - `GET /produtos` → qualquer usuário autenticado
   - `POST /produtos` → apenas quem tem a role `Produtos.Escrever`

## 1. Configurar o Entra ID (uma vez)

1. Portal Azure → **Microsoft Entra ID → App registrations → New registration** (ex.: `api-produtos`)
2. **Expose an API** → defina o Application ID URI (ex.: `api://<client-id>`) e adicione um scope (ex.: `Produtos.Ler`)
3. **App roles** → crie a role `Produtos.Escrever` (Allowed member types: Users/Groups)
4. **Enterprise applications → api-produtos → Users and groups** → atribua a role a um usuário
5. Para usar o Azure CLI no passo 3 abaixo: em **Expose an API → Add a client application**, autorize o client id do Azure CLI `04b07795-8ddb-461a-bbee-02f9e1bf7b46`

## 2. Subir o ambiente

```bash
cp .env.example .env          # preencha AZURE_TENANT_ID e AZURE_AUDIENCE
docker compose up --build
```

## 3. Testar

```bash
# Sem token -> 403 "token ausente..."
curl -i localhost:8080/produtos

# Token inválido -> 403 "token inválido..."
curl -i -H "Authorization: Bearer abc.def.ghi" localhost:8080/produtos

# Token real da Microsoft
az login
TOKEN=$(az account get-access-token --resource "$AZURE_AUDIENCE" --query accessToken -o tsv)

curl -i -H "Authorization: Bearer $TOKEN" localhost:8080/produtos     # 200
curl -i -X POST -H "Authorization: Bearer $TOKEN" \
     -d '{"nome":"Monitor"}' localhost:8080/produtos                   # 201 só com a role
```

Dica: cole o token em https://jwt.ms para mostrar as claims (`iss`, `aud`, `exp`, `roles`) para a turma.

### Postman

Importe `postman/treinamento-opa.postman_collection.json`, preencha as variáveis da collection
(`tenantId`, `audience`, `clientId`, `clientSecret`) e rode **Obter token**: o token fica salvo em `{{token}}`.

## 4. Conversar direto com o OPA (sem o serviço Go)

```bash
curl -s localhost:8181/v1/data/authz -d '{
  "input": {"method": "GET", "path": "/produtos", "authorization": "Bearer abc"}
}'
```

## 5. Rodar os testes da política

```bash
docker run --rm -v "$PWD/opa:/opa" openpolicyagent/opa:1.21.0-static test /opa -v
```

## Ideias de exercícios

- Liberar `DELETE /produtos` só para a role `Produtos.Admin`
- Negar acesso fora do horário comercial (`time.clock(time.now_ns())`)
- Exigir um scope específico (`claims.scp`) em vez de role
- Alterar a política, rodar `docker compose up --build` e mostrar que o serviço Go não mudou nada
