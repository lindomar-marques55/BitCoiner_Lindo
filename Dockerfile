# Usa a imagem oficial do Node.js (versão leve baseada em Alpine Linux)
FROM node:18-alpine

# Define o diretório de trabalho dentro do contêiner
WORKDIR /usr/src/app

# Copia apenas os arquivos de dependências primeiro, para otimizar o cache do Docker
COPY package*.json ./

# Instala as dependências do projeto
RUN npm install

# Copia o restante do código da aplicação para dentro do contêiner
COPY . .

# Informa ao Docker que o contêiner escutará na porta 3000
EXPOSE 3000

# Comando padrão para iniciar a aplicação
CMD [ "npm", "start" ]
