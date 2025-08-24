require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const porta = process.env.PORT || 10000; // Render usa porta 10000
const app = express();

// Middlewares com logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
    next();
});

app.use(express.json());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const JWT_SECRET = process.env.JWT_SECRET || 'seu_jwt_secret_aqui';
const SALT_ROUNDS = 10;

// Configuração do PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { 
        rejectUnauthorized: false 
    } : false
});

// Testar conexão com o banco
pool.on('connect', () => {
    console.log('✅ Conectado ao PostgreSQL');
});

pool.on('error', (err) => {
    console.error('❌ Erro na conexão PostgreSQL:', err);
});

// Configuração do Multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!fs.existsSync('uploads')) {
            fs.mkdirSync('uploads', { recursive: true });
        }
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (ext === '.pdf') {
            cb(null, true);
        } else {
            cb(new Error('Apenas arquivos PDF são permitidos.'), false);
        }
    },
    limits: { fileSize: 1024 * 1024 * 30 }
});

// ==================== ROTAS PRINCIPAIS ====================

// Rota raiz - TESTE
app.get('/', (req, res) => {
    res.json({ 
        message: 'Backend TCC SENAI Online! 🚀',
        status: 'operational',
        timestamp: new Date().toISOString(),
        routes: [
            '/health',
            '/test-db',
            '/login',
            '/cadastrar_usuario',
            '/listar_usuarios',
            '/listar_cursos',
            '/listar_tccs'
        ]
    });
});

// Health check
app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ 
            status: 'OK', 
            database: 'connected',
            timestamp: new Date().toISOString() 
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'ERROR', 
            database: 'disconnected',
            error: error.message 
        });
    }
});

// Teste de banco de dados
app.get('/test-db', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW() as time, version() as version');
        res.json({ 
            success: true, 
            time: result.rows[0].time,
            version: result.rows[0].version 
        });
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// ==================== ROTAS DE USUÁRIO ====================

app.post('/login', async (req, res) => {
    console.log('Login attempt:', req.body);
    const { email, senha } = req.body;
    
    if (!email || !senha) {
        return res.status(400).json({ erro: 'Email e senha são obrigatórios.' });
    }
    
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ erro: 'Email ou senha incorretos.' });
        }
        
        const usuario = result.rows[0];
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha);
        
        if (!senhaCorreta) {
            return res.status(401).json({ erro: 'Email ou senha incorretos.' });
        }
        
        const token = jwt.sign(
            { id: usuario.id, tipo: usuario.tipo, email: usuario.email },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            mensagem: 'Login bem-sucedido!',
            token,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                tipo: usuario.tipo
            }
        });
    } catch (err) {
        console.error('Erro no login:', err);
        res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
});

// ==================== ROTAS PÚBLICAS (para teste) ====================

app.get('/listar_cursos', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, curso FROM cursos ORDER BY curso');
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao listar cursos:', error);
        res.status(500).json({ erro: 'Erro ao listar cursos' });
    }
});

app.get('/listar_tccs', async (req, res) => {
    try {
        const { status } = req.query;
        let query = `
            SELECT tccs.*, cursos.curso 
            FROM tccs 
            JOIN cursos ON tccs.curso_id = cursos.id
        `;
        let params = [];
        
        if (status) {
            query += ' WHERE tccs.status = $1';
            params.push(status);
        }
        
        query += ' ORDER BY tccs.titulo';
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao listar TCCs:', error);
        res.status(500).json({ erro: 'Erro ao listar TCCs' });
    }
});

// ==================== INICIALIZAÇÃO ====================

// Garantir que a pasta uploads existe
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads', { recursive: true });
}

// Servir arquivos estáticos
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Rota de fallback para 404
app.use('*', (req, res) => {
    res.status(404).json({ 
        error: 'Rota não encontrada',
        path: req.originalUrl,
        available_routes: [
            'GET /',
            'GET /health',
            'GET /test-db',
            'POST /login',
            'GET /listar_cursos',
            'GET /listar_tccs'
        ]
    });
});

// Middleware de erro
app.use((err, req, res, next) => {
    console.error('Erro:', err);
    res.status(500).json({ 
        error: 'Erro interno do servidor',
        message: err.message 
    });
});

// Iniciar servidor
app.listen(porta, '0.0.0.0', () => {
    console.log(`🚀 Servidor rodando na porta ${porta}`);
    console.log(`🌍 Ambiente: ${process.env.NODE_ENV || 'development'}`);
    console.log(`📊 Database URL: ${process.env.DATABASE_URL ? 'Configurada' : 'Não configurada'}`);
});
