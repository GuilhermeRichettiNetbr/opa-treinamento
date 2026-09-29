FROM openpolicyagent/opa:1.21.0-static

# A política fica DENTRO da imagem do OPA
COPY policy/ /policies/

EXPOSE 8181

CMD ["run", "--server", "--addr=0.0.0.0:8181", "--log-level=info", "/policies"]
