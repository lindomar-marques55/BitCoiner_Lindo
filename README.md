# BitCoiner Lindo

Aplicação de monitoramento de Bitcoin e banco de dados Postgres, totalmente conteinerizada com Docker.

---

## Guia de Instalação: Ubuntu Server + CasaOS

Como o projeto já está no GitHub, o processo de instalação no seu servidor é bem direto. Você pode usar o Terminal (SSH) ou a Interface do CasaOS.

### Opção 1: Via Terminal (Recomendado)

Siga estes passos no seu Ubuntu Server:

1. **Acesse o servidor via SSH**:
   ```bash
   ssh seu-usuario@ip-do-servidor
   ```

2. **Clone o repositório**:
   ```bash
   git clone https://github.com/lindomar-marques55/BitCoiner_Lindo.git
   cd BitCoiner_Lindo
   ```

3. **Suba os containers**:
   ```bash
   docker compose up -d
   ```

4. **Acesse a aplicação**:
   Abra no seu navegador: `http://ip-do-servidor:3000`

---

### Opção 2: Via Interface CasaOS

O CasaOS permite importar configurações do `docker-compose` facilmente:

1. No Dashboard do CasaOS, clique em **App Store**.
2. No canto superior direito, clique em **Custom Install**.
3. Clique em **Import** (ícone de seta ao lado do "X").
4. Selecione **Docker Compose**.
5. Copie e cole o conteúdo do arquivo `docker-compose.yml` deste repositório.
6. Clique em **Submit**.
7. Preencha o nome do app (ex: `BitCoiner Lindo`) e clique em **Install**.

## Notas Importantes:

> [!WARNING]
> **Portas**: Verifique se a porta `3000` (App) e `5432` (Banco de Dados) não estão em uso por outros apps no seu servidor.

> [!TIP]
> **Atualizações**: No futuro, para atualizar o código no servidor, basta rodar:
> `git pull` e depois `docker compose up -d --build`
