const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;
app.use(express.json()); // Parsing JSON body
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
    }
}));
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012'; // 32 chars
const IV_LENGTH = 16;

function encryptKey(text) {
    if (!text) return null;
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptKey(text) {
    if (!text) return null;
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

function maskKey(text) {
    if (!text || text.length < 2) return '';
    return '*'.repeat(Math.max(12, text.length - 2)) + text.slice(-2);
}

// Configuração PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER || 'user',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'btc_tracker',
  password: process.env.DB_PASSWORD || 'password',
  port: parseInt(process.env.DB_PORT || '5432', 10),
});

// Inicialização das tabelas com Retry
async function initDB(retries = 5) {
  while (retries) {
    try {
      const client = await pool.connect();
      try {
        await client.query(`
          CREATE TABLE IF NOT EXISTS btc_history (
            timestamp BIGINT PRIMARY KEY,
            open NUMERIC,
            close NUMERIC,
            high NUMERIC,
            low NUMERIC,
            volume NUMERIC
          )
        `);
        await client.query(`
          CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            enc_access_id TEXT,
            enc_secret_key TEXT,
            keys_saved_at BIGINT
          )
        `);
        // Adiciona colunas novas sem quebrar tabelas antigas (Migration)
        await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;`);
        await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_token TEXT;`);
        await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_chat_id VARCHAR(50);`);
        
        await client.query(`
          CREATE TABLE IF NOT EXISTS global_settings (
            setting_key VARCHAR(50) PRIMARY KEY,
            setting_value VARCHAR(255)
          )
        `);
        console.log("Banco de dados verificado. Tabelas prontas.");
        return;
      } finally {
        client.release();
      }
    } catch (e) {
      console.error(`Tentando conectar ao banco. Tentativas restantes: ${retries - 1}`);
      retries -= 1;
      await new Promise(res => setTimeout(res, 3000));
    }
  }
}
initDB().catch(console.error);

// Middleware Jwt
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Nao autorizado' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Sessao expirada' });
        req.user = user;
        next();
    });
}

// Rotas de Autenticacao
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({error: 'Insira e-mail e senha.'});
    
    // Verificacao do formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(username)) return res.status(400).json({error: 'Por favor, insira um e-mail válido.'});
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Se for o primeiro usuário registrando no sistema, ele ganha privilégios de Admin vitalícios.
        const countRes = await pool.query('SELECT COUNT(*) FROM users');
        const count = parseInt(countRes.rows[0].count, 10);
        const isAdmin = count === 0;

        await pool.query('INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, $3)', [username, hashedPassword, isAdmin]);
        res.status(201).json({ message: 'Registrado com sucesso' });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({error: 'Nome de usuário já existe.'}); 
        res.status(500).json({error: 'Erro no servidor'});
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(401).json({error: 'Usuário ou senha incorretos.'});
        
        const user = result.rows[0];
        const validPass = await bcrypt.compare(password, user.password_hash);
        if (!validPass) return res.status(401).json({error: 'Usuário ou senha incorretos.'});

        const isAdmin = user.is_admin || false;
        const token = jwt.sign({ id: user.id, username: user.username, is_admin: isAdmin }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, username: user.username, is_admin: isAdmin });
    } catch (err) {
        res.status(500).json({error: 'Erro no servidor'});
    }
});

// Middleware Admin
function authenticateAdmin(req, res, next) {
    authenticateToken(req, res, () => {
        if (!req.user || !req.user.is_admin) return res.status(403).json({ error: 'Acesso restrito a administradores.' });
        next();
    });
}

// Rotas Admin
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, is_admin FROM users ORDER BY id ASC');
        res.json(result.rows);
    } catch(e) {
        res.status(500).json({ error: 'Erro ao buscar usuários' });
    }
});

app.post('/api/admin/users/:id/elevate', authenticateAdmin, async (req, res) => {
    try {
        await pool.query('UPDATE users SET is_admin = TRUE WHERE id = $1', [req.params.id]);
        res.json({ message: 'Usuário promovido a Admin.' });
    } catch(e) {
        res.status(500).json({ error: 'Erro ao promover usuário' });
    }
});

app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        // Impede o admin de deletar a si mesmo, e garante a remoção da conta completa
        if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Você não pode deletar a si mesmo.' });
        await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
        res.json({ message: 'Usuário deletado permanentemente.' });
    } catch(e) {
        res.status(500).json({ error: 'Erro ao deletar usuário' });
    }
});

app.post('/api/auth/verify-password', authenticateToken, async (req, res) => {
    const { password } = req.body;
    try {
        const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
        const validPass = await bcrypt.compare(password, result.rows[0].password_hash);
        if (validPass) res.json({ valid: true });
        else res.status(401).json({ valid: false, error: 'Senha Incompleta ou Errada' });
    } catch(e) {
        res.status(500).json({ error: 'Erro de verificação' });
    }
});

// Rotas exclusivas do Usuário - API Keys (Lógica Server-side)
app.get('/api/keys', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT enc_access_id, enc_secret_key, keys_saved_at FROM users WHERE id = $1', [req.user.id]);
        const user = result.rows[0];
        if (!user || !user.enc_access_id) return res.json({ hasKeys: false });

        const now = Date.now();
        const thirtyDays = 30 * 24 * 60 * 60 * 1000;
        if (user.keys_saved_at && (now - parseInt(user.keys_saved_at)) > thirtyDays) {
            await pool.query('UPDATE users SET enc_access_id = NULL, enc_secret_key = NULL, keys_saved_at = NULL WHERE id = $1', [req.user.id]);
            return res.json({ hasKeys: false, expired: true });
        }

        const accessRaw = decryptKey(user.enc_access_id);
        const secretRaw = decryptKey(user.enc_secret_key);

        res.json({
            hasKeys: true,
            maskedAccess: maskKey(accessRaw),
            maskedSecret: maskKey(secretRaw)
        });
    } catch(e) {
        res.status(500).json({error: 'Erro interno'});
    }
});

app.post('/api/keys', authenticateToken, async (req, res) => {
    const { action, accessId, secretKey } = req.body;
    try {
        if (action === 'delete') {
            await pool.query('UPDATE users SET enc_access_id = NULL, enc_secret_key = NULL, keys_saved_at = NULL WHERE id = $1', [req.user.id]);
            return res.json({ message: 'Chaves deletadas' });
        }
        
        const encAccess = encryptKey(accessId);
        const encSecret = encryptKey(secretKey);
        const now = Date.now();
        
        await pool.query('UPDATE users SET enc_access_id = $1, enc_secret_key = $2, keys_saved_at = $3 WHERE id = $4', 
            [encAccess, encSecret, now, req.user.id]);
            
        res.json({ message: 'Salvas com sucesso' });
    } catch(e) {
        res.status(500).json({error: 'Erro interno'});
    }
});

// -------------------------------------------------------------------------------------------------
// TELEGRAM E MOTOR TRADER EM BACKGROUND (CERÉBRO AUTÔNOMO)
// -------------------------------------------------------------------------------------------------
app.get('/api/telegram', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT telegram_token, telegram_chat_id FROM users WHERE id = $1', [req.user.id]);
        res.json(result.rows[0] || {});
    } catch(e) { res.status(500).json({error: 'Erro interno'}); }
});

app.post('/api/telegram', authenticateToken, async (req, res) => {
    const { token, chatId } = req.body;
    try {
        // Envia mensagem de validação/confirmação para o Telegram
        const telegramRes = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                chat_id: chatId, 
                text: '✅ *Conexão Estabelecida!*\n\nO seu Cérebro Trader do BitCoiner Lindo agora está conectado e enviará alertas de Compra/Venda diretamente aqui no Telegram.', 
                parse_mode: 'Markdown'
            })
        });

        if (!telegramRes.ok) {
            return res.status(400).json({error: 'Token ou Chat ID inválidos. O robô não conseguiu enviar a mensagem de teste.'});
        }

        await pool.query('UPDATE users SET telegram_token = $1, telegram_chat_id = $2 WHERE id = $3', [token, chatId, req.user.id]);
        res.json({ message: 'Conexão Telegram Salva e Validada!' });
    } catch(e) { res.status(500).json({error: 'Erro interno ao salvar.'}); }
});

app.get('/api/previsao', authenticateToken, async (req, res) => {
    try {
        const clientIns = await pool.connect();
        const memory = await clientIns.query('SELECT timestamp, close, volume FROM btc_history ORDER BY timestamp DESC LIMIT 100');
        clientIns.release();
        
        if (memory.rows.length >= 20) {
            const dataP = memory.rows.map(r => ({ open: 0, closePrice: Number(r.close), high: 0, low: 0, volume: Number(r.volume), ts: parseInt(r.timestamp, 10) }));
            const validDays = Math.min(80, dataP.length - 19);
            
            const processedDays = [];
            for (let i = 0; i < validDays; i++) {
                const bb = calcularBandasDeBollingerServidor(dataP, i, 20);
                const dateStr = new Date(dataP[i].ts).toLocaleDateString('pt-BR', {timeZone:'UTC'});
                const vol = dataP[i].volume.toFixed(2);
                const close = dataP[i].closePrice.toFixed(2);
                let smaStr = bb ? bb.middle.toFixed(2) : '-';
                processedDays.push(`Dia ${dateStr}: Fechamento=$${close} | Volume=${vol} BTC | SMA(20)=$${smaStr}`);
            }
            
            const rawData = processedDays.reverse().join('\n');
            const systemPrompt = `Você é um Analista Quantitativo Sênior autônomo. Abaixo está o histórico diário do Bitcoin (BTC/USDT) contendo o Preço de Fechamento, Volume Transacionado e a Banda Central de Bollinger (SMA de 20 períodos).\n\n${rawData}\n\nSua tarefa: Analise a tendência, volatilidade, força compradora (baseada no volume) e a relação entre preço e a média móvel (SMA). Com base nestes padrões matemáticos, preveja EXATAMENTE o preço de fechamento para os PRÓXIMOS 10 DIAS a partir do último dia informado.\n\nVocê DEVE responder APENAS no formato Markdown de uma lista enumerada, do "Dia 1:" ao "Dia 10:", contendo a data prevista na sequência do calendário e o preço de fechamento em dólares. NÃO inclua saudações, introduções ou explicações na resposta. Gere APENAS a lista da previsão e NADA MAIS. Exemplo: "1. 24/03/2026: $ 71,500.00"`;
            
            const ollamaRes = await fetch('http://192.168.100.193:11434/api/generate', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    model: 'llama3.2:3b', 
                    prompt: systemPrompt, 
                    stream: false,
                    options: { temperature: 0.1 }
                })
            });
            
            if (ollamaRes.ok) {
                const ollamaJson = await ollamaRes.json();
                res.json({ prediction: ollamaJson.response });
            } else {
                res.status(500).json({ error: "Falha na comunicação com o LLM Ollama." });
            }
        } else {
            res.status(400).json({ error: "Histórico INSUFICIENTE no banco de dados." });
        }
    } catch (e) {
        console.error('Erro /api/previsao:', e);
        res.status(500).json({ error: "Erro interno ao processar a previsão." });
    }
});

app.delete('/api/telegram', authenticateToken, async (req, res) => {
    try {
        await pool.query('UPDATE users SET telegram_token = NULL, telegram_chat_id = NULL WHERE id = $1', [req.user.id]);
        res.json({ message: 'Robô do Telegram Desativado da Conta.' });
    } catch(e) { res.status(500).json({error: 'Erro interno.'}); }
});

// MOTOR TRADER (Roda em loop independente dos navegadores abertos)
let lastTradeAction = 'Manter';
let cerebroIntervalTimer = null;
let currentCerebroIntervalMs = 5 * 60 * 1000;

async function restartCerebroTimer() {
    try {
        const res = await pool.query("SELECT setting_value FROM global_settings WHERE setting_key = 'update_interval'");
        if (res.rows.length > 0) {
            const mins = parseFloat(res.rows[0].setting_value);
            if (mins > 0) currentCerebroIntervalMs = mins * 60 * 1000;
        }
    } catch(e) {}
    
    if (cerebroIntervalTimer) clearInterval(cerebroIntervalTimer);
    console.log('[🚀 BitcoinerLindo] Cerebro Trader Ativado. Rodando em background...');
    cerebroIntervalTimer = setInterval(loopCerebroTrader, currentCerebroIntervalMs);
}

function calcularBandasDeBollingerServidor(dataItems, index, period = 20) {
    if (index + period > dataItems.length) return null;
    let sum = 0;
    for (let i = 0; i < period; i++) sum += dataItems[index + i].closePrice;
    const sma = sum / period;
    let varianceSum = 0;
    for (let i = 0; i < period; i++) varianceSum += Math.pow(dataItems[index + i].closePrice - sma, 2);
    const sd = Math.sqrt(varianceSum / period);
    return { upper: sma + 2 * sd, lower: sma - 2 * sd, middle: sma };
}

async function editarMensagemTg(token, chatId, messageId, novoTexto) {
    fetch(`https://api.telegram.org/bot${token}/editMessageText`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ chat_id: chatId, message_id: messageId, text: novoTexto, parse_mode: 'Markdown' })
    }).catch(()=>{});
}

async function alertarTelegram(acaoTradedoAviso, precoAtual, bb) {
    try {
        const mensagem = `🤖 *SINAL DO ROBÔ: ${acaoTradedoAviso.toUpperCase()}!*\n\nO Preço do Bitcoin rompeu a fronteira.\n💎 Preço Atual: *$${precoAtual.toLocaleString()}*\n🔴 Banda Superior (Vender): $${bb.upper.toFixed(2)}\n🟢 Banda Inferior (Comprar): $${bb.lower.toFixed(2)}\n\n*Ação sugerida. O que devemos fazer?*`;
        
        const tradeSide = acaoTradedoAviso.toUpperCase() === 'COMPRAR' ? 'BUY' : 'SELL';
        
        const inlineKeyboard = {
            inline_keyboard: [
                [{ text: `✅ Aprovar Execução a Mercado`, callback_data: `TRADE_MARKET_${tradeSide}` }],
                [{ text: `❌ Abortar Operação / Ignorar`, callback_data: `TRADE_ABORT` }]
            ]
        };

        const client = await pool.connect();
        const usersT = await client.query('SELECT telegram_token, telegram_chat_id FROM users WHERE telegram_token IS NOT NULL AND telegram_chat_id IS NOT NULL');
        client.release();
        
        for (const tgUser of usersT.rows) {
            const endpoint = `https://api.telegram.org/bot${tgUser.telegram_token}/sendMessage`;
            fetch(endpoint, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ 
                    chat_id: tgUser.telegram_chat_id, 
                    text: mensagem, 
                    parse_mode: 'Markdown',
                    reply_markup: inlineKeyboard
                })
            }).catch(e => console.error("Erro interno ao contatar servidor Telegram"));
        }
    } catch(e) { console.error('Falha no Alert_tg', e); }
}

async function loopCerebroTrader() {
    try {
        const client = await pool.connect();
        let lastDate = null;
        try {
            const resDate = await client.query('SELECT MAX(timestamp) as last_date FROM btc_history');
            lastDate = resDate.rows[0].last_date ? parseInt(resDate.rows[0].last_date, 10) : null;
        } finally { client.release(); }

        const responseApi = await fetch('https://api.coinex.com/v2/spot/kline?market=BTCUSDT&period=1day&limit=100');
        if (!responseApi.ok) return;
        const apiData = await responseApi.json();
        const itensFeitos = apiData.data || [];
        
        const clientIns = await pool.connect();
        try {
            for (const item of itensFeitos) {
                 let ts, open, close, high, low, volume;
                 if (Array.isArray(item)) {
                    ts = Number(item[0]); open = parseFloat(item[1]); close = parseFloat(item[2]); high = parseFloat(item[3]); low = parseFloat(item[4]); volume = parseFloat(item[5]);
                 } else {
                    ts = Number(item.created_at || item.time); open = parseFloat(item.open); close = parseFloat(item.close); high = parseFloat(item.high); low = parseFloat(item.low); volume = parseFloat(item.volume || item.value);
                 }
                 if (!lastDate || ts >= lastDate) { // Salva no banco de dados
                    await clientIns.query(`
                      INSERT INTO btc_history (timestamp, open, close, high, low, volume)
                      VALUES ($1, $2, $3, $4, $5, $6)
                      ON CONFLICT (timestamp) DO UPDATE SET open=EXCLUDED.open, close=EXCLUDED.close, high=EXCLUDED.high, low=EXCLUDED.low, volume=EXCLUDED.volume
                    `, [ts, open, close, high, low, volume]);
                 }
            }

            // Lê do banco ordenado DESC (o [0] é o mais atual)
            const memory = await clientIns.query('SELECT * FROM btc_history ORDER BY timestamp DESC LIMIT 60');
            const dataP = memory.rows.map(r => ({ open: Number(r.open), closePrice: Number(r.close), high: Number(r.high), low: Number(r.low) }));
            if (dataP.length < 20) return; // DB muito vazio

            const bollingerHoje = calcularBandasDeBollingerServidor(dataP, 0, 20);
            if (bollingerHoje) {
                const fechamentoAgora = dataP[0].closePrice;
                let acaoAgora = 'Manter';
                if (fechamentoAgora > bollingerHoje.upper) acaoAgora = 'Vender';
                else if (fechamentoAgora < bollingerHoje.lower) acaoAgora = 'Comprar';

                // Dispara o alerta apenas se for um Sinal Forte que mudou recém.
                if (acaoAgora !== 'Manter' && acaoAgora !== lastTradeAction) {
                    lastTradeAction = acaoAgora;
                    await alertarTelegram(acaoAgora, fechamentoAgora, bollingerHoje);
                } else if (acaoAgora === 'Manter') {
                    lastTradeAction = 'Manter'; // Reinicia o engatilho para permitir um proximo sinal livre
                }
            }
        } finally { clientIns.release(); }
    } catch (e) { console.error('Motor falha na rede temporal:', e.message); }
}

// Roda o temporizador customizado
setTimeout(() => {
    restartCerebroTimer();
    loopCerebroTrader(); // roda o gatilho inicial 5 seg apos
}, 5000); 

// -------------------------------------------------------------------------------------------------
// MOTOR EXECUTOR DE TRANSAÇÕES FINANCEIRAS (COINEX)
// -------------------------------------------------------------------------------------------------
async function iniciarFluxoDeTradeCoinEx(tgChatId, side, tgToken, tgMessageId) {
    const editMsg = (msg) => editarMensagemTg(tgToken, tgChatId, tgMessageId, msg);
    
    try {
        // 1. Pegar chaves de api (Ação perigosa)
        const client = await pool.connect();
        const resUser = await client.query('SELECT enc_access_id, enc_secret_key FROM users WHERE telegram_chat_id = $1 LIMIT 1', [tgChatId.toString()]);
        client.release();
        
        if (resUser.rows.length === 0 || !resUser.rows[0].enc_access_id) 
            return editMsg("❌ Erro: Chaves API da CoinEx não cadastradas para o seu usuário. Acesse o site e salve suas chaves primeiro.");
        
        const accessId = decryptKey(resUser.rows[0].enc_access_id);
        let secretKey = '';
        try {
            secretKey = decryptKey(resUser.rows[0].enc_secret_key);
            if (!secretKey) throw new Error('chave vazia');
        } catch(e) { return editMsg("❌ Erro fatal: O Cofre de chaves AES-256 da CoinEx falhou ao ser destrancado."); }

        // Módulo V2 de Assinatura CoinEx
        const callCoinEx = async (method, path, body = null) => {
            const timestamp = Date.now().toString();
            let queryStr = '';
            if (method.toUpperCase() === 'GET' && body) {
                queryStr = new URLSearchParams(body).toString();
                path = path + '?' + queryStr;
            }
            
            let preparedBody = '';
            if (body && method.toUpperCase() !== 'GET') preparedBody = JSON.stringify(body);
            
            const stringToSign = method.toUpperCase() + path + preparedBody + timestamp;
            const signature = crypto.createHmac('sha256', secretKey).update(stringToSign).digest('hex').toLowerCase();
            
            const headers = {
                'X-COINEX-KEY': accessId,
                'X-COINEX-TIMESTAMP': timestamp,
                'X-COINEX-SIGN': signature
            };
            if(body && method.toUpperCase() !== 'GET') headers['Content-Type'] = 'application/json';
            
            const reqUrl = 'https://api.coinex.com' + path;
            const actBody = (method.toUpperCase()!=='GET' && body) ? JSON.stringify(body) : undefined;
            
            const rr = await fetch(reqUrl, { method: method.toUpperCase(), headers, body: actBody });
            return await rr.json();
        };

        // 2. CHECK 24h TRADES
        const finishedRes = await callCoinEx('GET', '/v2/spot/finished-order', { market: 'BTCUSDT', market_type: 'SPOT', limit: '5', page: '1' });
        console.log('[TRADE] finished-order resp code:', finishedRes.code, 'qtd:', finishedRes.data?.length ?? 'N/A');
        if (finishedRes.code === 0 && finishedRes.data && finishedRes.data.length > 0) {
            const raw = finishedRes.data[0].created_at;
            const latestTradeTime = parseInt(raw, 10);
            const diffMs = Date.now() - latestTradeTime;
            console.log('[TRADE] ultima ordem em:', raw, '| diff ms:', diffMs, '| 24h ms:', 24*60*60*1000);
            if (diffMs < 24 * 60 * 60 * 1000) {
                return editMsg(`🛡️ *Alerta de Segurança: Abortado*\nExiste uma Ordem executada nas últimas 24 Horas!\n_(Última ordem: ${new Date(latestTradeTime).toLocaleString('pt-BR')})_\n\nAguarde o prazo expirando para operar novamente.`);
            }
        } else {
            console.log('[TRADE] Nenhuma ordem recente, ou erro na API:', finishedRes.message);
        }

        // 3. CANCEL OPEN ORDERS (individualmente por order_id)
        const pendingRes = await callCoinEx('GET', '/v2/spot/pending-order', { market: 'BTCUSDT', market_type: 'SPOT', limit: '100', page: '1' });
        console.log('[TRADE] pending-order resp code:', pendingRes.code, 'qtd:', pendingRes.data?.length ?? 'N/A', 'msg:', pendingRes.message);
        if (pendingRes.code === 0 && pendingRes.data && pendingRes.data.length > 0) {
            editMsg(`🗑️ *${pendingRes.data.length} Ordem(ns) Pendente(s) encontradas!* Cancelando uma a uma...`);
            let cancelFailed = false;
            for (const order of pendingRes.data) {
                const cancelRes = await callCoinEx('POST', '/v2/spot/cancel-order', { market: 'BTCUSDT', market_type: 'SPOT', order_id: order.order_id });
                console.log('[TRADE] cancel-order', order.order_id, 'resp code:', cancelRes.code, cancelRes.message);
                if (cancelRes.code !== 0) {
                    cancelFailed = true;
                    return editMsg(`❌ Falha ao cancelar ordem \`#${order.order_id}\`.\nCoinEx respondeu: \`${cancelRes.message}\``);
                }
            }
            if (!cancelFailed) editMsg('✅ Todas as ordens pendentes canceladas! Liberando pista para Market Order...');
        } else {
            editMsg('✅ Pista já estava limpa. Calculando margens...');
        }

        // 4. FIND MARKET LIMITS
        let minAmountBase = "0.0001"; // default 0.0001 BTC
        let minAmountQuote = "5.0"; // default 5 USDT
        const mktRes = await callCoinEx('GET', '/v2/spot/market', { market: 'BTCUSDT' });
        if (mktRes.code === 0 && mktRes.data && mktRes.data.length > 0) {
            const maList = mktRes.data[0];
            if (maList.min_amount) minAmountBase = maList.min_amount.toString();
        }
        
        let finalAmountSent = minAmountBase;
        if (side.toLowerCase() === 'buy') {
            const tickerResult = await fetch('https://api.coinex.com/v2/spot/ticker?market=BTCUSDT').then(r=>r.json());
            if (tickerResult.code === 0 && tickerResult.data && tickerResult.data.length>0) {
                const currentPrice = parseFloat(tickerResult.data[0].last);
                // Compra precisa dizer a quantidade em dolares, adicionamos 5% de gordura na tarifa
                const dollarValue = currentPrice * parseFloat(minAmountBase) * 1.05;
                finalAmountSent = dollarValue.toFixed(4).toString(); 
            } else {
                finalAmountSent = "10.0"; // failback 10$
            }
        }

        // 5. THE TRIGGER!  
        editMsg(`🔥 Preparando Canhões! Ordem solicitada: \`${side.toUpperCase()}\` A MERCADO. Tamanho faturado: \`${finalAmountSent}\``);
        
        const orderRes = await callCoinEx('POST', '/v2/spot/order', {
            market: 'BTCUSDT',
            market_type: 'SPOT',
            side: side.toLowerCase(),
            type: 'market',
            amount: finalAmountSent
        });

        if (orderRes.code === 0) {
            editMsg(`🎉 *BOMBA LANÇADA COM SUCESSO!* 🚀\nA Ordem a Mercado cruzou Wall Street!\n\n🔹 Lado: *${side.toUpperCase()}*\n🔹 ID_Bolsa: \`${orderRes.data.order_id}\`\n🔹 Total Informado Pelo Robô: \`${finalAmountSent}\`\n\nPode relaxar as costas na cadeira. O Bitcoin Tracker já faturou o sinal e fez todo o trabalho duro pra você!`);
        } else {
            editMsg(`❌ *Falha de Operação Tática na Exchange.*\nCoinEx negou nosso pacote informando:\n\`${orderRes.message}\`\n\nPossibilidade comum: Você não tem esse saldo exato disponível para essa conversão agora ou há restrições atípicas.`);
        }

    } catch (e) {
        editMsg(`☠️ Pane elétrica detectada durante o Flow Bancário. Robô desarmado por proteção.`);
        console.error("Exec Flow Exception:", e);
    }
}

// -------------------------------------------------------------------------------------------------
// ESCUTA LONG POLLING (OUVINDO CLIQUES NOS BOTÕES DO TELEGRAM)
// -------------------------------------------------------------------------------------------------
let lastTgUpdateId = 0;
async function pollTelegramUpdates() {
    try {
        const client = await pool.connect();
        // Na prática, puxamos os bots ativos, no caso do personal tracker só tem o admin em cache ativo
        const usersT = await client.query("SELECT telegram_token FROM users WHERE telegram_token IS NOT NULL AND telegram_chat_id IS NOT NULL LIMIT 1");
        client.release();
        
        if (usersT.rows.length > 0) {
            const tgToken = usersT.rows[0].telegram_token;
            const res = await fetch(`https://api.telegram.org/bot${tgToken}/getUpdates?offset=${lastTgUpdateId + 1}&timeout=30`);
            if (res.ok) {
                const json = await res.json();
                if (json.ok && json.result.length > 0) {
                    for (const update of json.result) {
                        lastTgUpdateId = update.update_id;
                        
                        // Capturando se apertaram algum Botão de Trade Inline
                        if (update.callback_query) {
                            const cb = update.callback_query;
                            const cqData = cb.data; 
                            const chatId = cb.message.chat.id;
                            const messageId = cb.message.message_id;
                            
                            // Desliga a rodela de loading do botão no celular do usuario
                            fetch(`https://api.telegram.org/bot${tgToken}/answerCallbackQuery`, {
                                method: 'POST', headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({ callback_query_id: cb.id })
                            }).catch(()=>{});
                            
                            if (cqData === 'TRADE_ABORT') {
                                editarMensagemTg(tgToken, chatId, messageId, "❌ Ordem ABORTADA explicitamente após comando do General.");
                            } else if (cqData.startsWith('TRADE_MARKET_')) {
                                const side = cqData.replace('TRADE_MARKET_', ''); // "BUY" ou "SELL"
                                editarMensagemTg(tgToken, chatId, messageId, `⚙️ Confirmação Recebida! Iniciando engate à bolsa de Wall Street via CoinEx API v2 para ${side}...`);
                                iniciarFluxoDeTradeCoinEx(chatId, side, tgToken, messageId);
                            }
                        } else if (update.message && update.message.text === '/status') {
                            const chatId = update.message.chat.id;
                            try {
                                const clientIns = await pool.connect();
                                const memory = await clientIns.query('SELECT * FROM btc_history ORDER BY timestamp DESC LIMIT 60');
                                clientIns.release();
                                if (memory.rows.length >= 20) {
                                    const dataP = memory.rows.map(r => ({ open: Number(r.open), closePrice: Number(r.close), high: Number(r.high), low: Number(r.low), volume: Number(r.volume), ts: parseInt(r.timestamp, 10) }));
                                    const bollingerHoje = calcularBandasDeBollingerServidor(dataP, 0, 20);
                                    if(bollingerHoje) {
                                        const hj = dataP[0];
                                        const tsDate = new Date(hj.ts);
                                        let acaoAgora = 'Estável';
                                        if (hj.closePrice > bollingerHoje.upper) acaoAgora = 'Vender';
                                        else if (hj.closePrice < bollingerHoje.lower) acaoAgora = 'Comprar';

                                        const msgStatus = `📊 *Status Atual do Mercado (BTC/USDT)*\n\n` +
                                            `🕐 *Horário:* ${tsDate.toLocaleDateString('pt-BR', {timeZone:'UTC'})}, ${tsDate.toLocaleTimeString('pt-BR', {timeZone:'UTC'})} (UTC) (Brasília)\n` +
                                            `📈 *Abertura:* R\\$ ${hj.open.toLocaleString('pt-BR', {minimumFractionDigits: 3, maximumFractionDigits: 3})}\n` +
                                            `📉 *Fechamento:* R\\$ ${hj.closePrice.toLocaleString('pt-BR', {minimumFractionDigits: 3, maximumFractionDigits: 3})}\n` +
                                            `🔺 *Máxima:* R\\$ ${hj.high.toLocaleString('pt-BR', {minimumFractionDigits: 3, maximumFractionDigits: 3})}\n` +
                                            `🔻 *Mínima:* R\\$ ${hj.low.toLocaleString('pt-BR', {minimumFractionDigits: 3, maximumFractionDigits: 3})}\n` +
                                            `📦 *Volume:* ${hj.volume.toLocaleString('pt-BR', {maximumFractionDigits: 4})} BTC\n\n` +
                                            `*Indicadores Técnicos (BB):*\n` +
                                            `🔴 *Sup:* R\\$ ${bollingerHoje.upper.toLocaleString('pt-BR', {minimumFractionDigits: 3, maximumFractionDigits: 3})}\n` +
                                            `🟡 *Méio:* R\\$ ${bollingerHoje.middle.toLocaleString('pt-BR', {minimumFractionDigits: 3, maximumFractionDigits: 3})}\n` +
                                            `🟢 *Inf:* R\\$ ${bollingerHoje.lower.toLocaleString('pt-BR', {minimumFractionDigits: 3, maximumFractionDigits: 3})}\n\n` +
                                            `${acaoAgora}`;

                                        fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
                                            method: 'POST', headers: {'Content-Type': 'application/json'},
                                            body: JSON.stringify({ chat_id: chatId, text: msgStatus, parse_mode: 'Markdown' })
                                        }).catch(()=>{});
                                    }
                                }
                            } catch (e) { console.error('Erro /status', e); }
                        } else if (update.message && update.message.text === '/previsao') {
                            const chatId = update.message.chat.id;
                            try {
                                const loadMsgRes = await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
                                    method: 'POST', headers: {'Content-Type': 'application/json'},
                                    body: JSON.stringify({ chat_id: chatId, text: "⏳ *Consultando Oráculo (IA Local)...*\nAnalisando o histórico diário gravado no banco de dados para realizar a previsão preditiva dos próximos 10 dias. Por favor aguarde...", parse_mode: 'Markdown' })
                                }).then(r=>r.json());
                                
                                const sMsgId = loadMsgRes.ok && loadMsgRes.result ? loadMsgRes.result.message_id : null;
                                const clientIns = await pool.connect();
                                const memory = await clientIns.query('SELECT timestamp, close, volume FROM btc_history ORDER BY timestamp DESC LIMIT 100');
                                clientIns.release();
                                
                                if (memory.rows.length >= 20) {
                                    const dataP = memory.rows.map(r => ({ open: 0, closePrice: Number(r.close), high: 0, low: 0, volume: Number(r.volume), ts: parseInt(r.timestamp, 10) }));
                                    const validDays = Math.min(80, dataP.length - 19);
                                    
                                    const processedDays = [];
                                    for (let i = 0; i < validDays; i++) {
                                        const bb = calcularBandasDeBollingerServidor(dataP, i, 20);
                                        const dateStr = new Date(dataP[i].ts).toLocaleDateString('pt-BR', {timeZone:'UTC'});
                                        const vol = dataP[i].volume.toFixed(2);
                                        const close = dataP[i].closePrice.toFixed(2);
                                        let smaStr = bb ? bb.middle.toFixed(2) : '-';
                                        processedDays.push(`Dia ${dateStr}: Fechamento=$${close} | Volume=${vol} BTC | SMA(20)=$${smaStr}`);
                                    }
                                    
                                    const rawData = processedDays.reverse().join('\n');
                                    const systemPrompt = `Você é um Analista Quantitativo Sênior autônomo. Abaixo está o histórico diário do Bitcoin (BTC/USDT) contendo o Preço de Fechamento, Volume Transacionado e a Banda Central de Bollinger (SMA de 20 períodos).\n\n${rawData}\n\nSua tarefa: Analise a tendência, volatilidade, força compradora (baseada no volume) e a relação entre preço e a média móvel (SMA). Com base nestes padrões matemáticos, preveja EXATAMENTE o preço de fechamento para os PRÓXIMOS 10 DIAS a partir do último dia informado.\n\nVocê DEVE responder APENAS no formato Markdown de uma lista enumerada, do "Dia 1:" ao "Dia 10:", contendo a data prevista na sequência do calendário e o preço de fechamento em dólares. NÃO inclua saudações, introduções ou explicações na resposta. Gere APENAS a lista da previsão e NADA MAIS. Exemplo: "1. 24/03/2026: $ 71,500.00"`;
                                    
                                    const ollamaRes = await fetch('http://192.168.100.193:11434/api/generate', {
                                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ model: 'llama3.2:3b', prompt: systemPrompt, stream: false })
                                    });
                                    
                                    if (ollamaRes.ok) {
                                        const ollamaJson = await ollamaRes.json();
                                        const finalMsg = `🔮 *Previsão do Cérebro (llama3.2)*\n_Baseado no rigor matemático dos últimos 80 dias e tendências do mercado._\n\n${ollamaJson.response}\n\n⚠️ *Aviso:* Isso é uma predição IA simulada e não garantia financeira.`;
                                        if (sMsgId) editarMensagemTg(tgToken, chatId, sMsgId, finalMsg);
                                        else fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ chat_id: chatId, text: finalMsg, parse_mode: 'Markdown' }) }).catch(()=>{});
                                    } else {
                                        if (sMsgId) editarMensagemTg(tgToken, chatId, sMsgId, "❌ Falha no Processamento: O motor Ollama local negou a inferência neural.");
                                    }
                                } else {
                                    if (sMsgId) editarMensagemTg(tgToken, chatId, sMsgId, "❌ Histórico INSUFICIENTE no banco de dados para criar uma matriz preditiva.");
                                }
                            } catch (e) {
                                console.error('Erro previsao:', e);
                            }
                        }
                    }
                }
            }
        }
    } catch(e) {}
    
    setTimeout(pollTelegramUpdates, 2000); // Roda 2 em 2 segundos para dar folego
}
setTimeout(pollTelegramUpdates, 15000); // Liga só dpois de 15seg do start do servidor

// -------------------------------------------------------------------------------------------------
// AJUSTE GLOBAL DE VELOCIDADE DO ROBÔ
// -------------------------------------------------------------------------------------------------
app.post('/api/settings/interval', authenticateToken, async (req, res) => {
    const { minutes } = req.body;
    const minsNum = parseFloat(minutes);
    if (!minsNum || minsNum <= 0) return res.status(400).json({error: 'Velocidade inválida.'});
    
    try {
        if (!req.user.is_admin) return res.status(403).json({error: 'Restrito. Apenas o Admin pode definir a velocidade Global do Robô.'});
        // Atualiza a velocidade mestre e refaz o timer dinamicamente no node
        await pool.query(
            "INSERT INTO global_settings (setting_key, setting_value) VALUES ('update_interval', $1) ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value",
            [minsNum.toString()]
        );
        restartCerebroTimer();
        res.json({ message: 'Velocidade atômica do Servidor atualizada' });
    } catch(e) {
        res.status(500).json({error: 'Erro grave no banco'});
    }
});

app.get('/api/settings/interval', async (req, res) => {
    try {
        const result = await pool.query("SELECT setting_value FROM global_settings WHERE setting_key = 'update_interval'");
        const mins = result.rows.length > 0 ? parseFloat(result.rows[0].setting_value) : 5;
        res.json({ minutes: mins });
    } catch(e) { res.status(500).json({ minutes: 5 }); }
});

// -------------------------------------------------------------------------------------------------
// Cache Histórico Compartilhado (Precisa estar logado para acessar via UI)
// -------------------------------------------------------------------------------------------------
app.get('/api/btc-history', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT MAX(timestamp) as last_date FROM btc_history');
      const lastDate = result.rows[0].last_date ? parseInt(result.rows[0].last_date, 10) : null;
      
      const response = await fetch('https://api.coinex.com/v2/spot/kline?market=BTCUSDT&period=1day&limit=100');
      if (!response.ok) {
          console.error(`Falha CoinEx: ${response.status}`);
      } else {
          const jsonResponse = await response.json();
          const coinexData = jsonResponse.data || [];
          
          for (const item of coinexData) {
             let ts, open, close, high, low, volume;
             if (Array.isArray(item)) {
                ts = Number(item[0]); open = parseFloat(item[1]); close = parseFloat(item[2]); high = parseFloat(item[3]); low = parseFloat(item[4]); volume = parseFloat(item[5]);
             } else {
                ts = Number(item.created_at || item.time); open = parseFloat(item.open); close = parseFloat(item.close); high = parseFloat(item.high); low = parseFloat(item.low); volume = parseFloat(item.volume || item.value);
             }
             if (!lastDate || ts >= lastDate) {
                await client.query(`
                  INSERT INTO btc_history (timestamp, open, close, high, low, volume)
                  VALUES ($1, $2, $3, $4, $5, $6)
                  ON CONFLICT (timestamp) DO UPDATE SET open=EXCLUDED.open, close=EXCLUDED.close, high=EXCLUDED.high, low=EXCLUDED.low, volume=EXCLUDED.volume
                `, [ts, open, close, high, low, volume]);
             }
          }
      }

      const finalResult = await client.query('SELECT * FROM btc_history ORDER BY timestamp ASC LIMIT 100');
      const formattedData = finalResult.rows.map(r => ({
          created_at: parseInt(r.timestamp, 10), open: r.open, close: r.close, high: r.high, low: r.low, volume: r.volume
      }));

      res.json({ code: 0, data: formattedData, message: "OK" });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Erro /db:', error);
    res.status(500).json({ error: 'Erro Servidor' });
  }
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
