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

const porta = process.env.PORT || 3000;
const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'seu_jwt_secret_aqui';
const SALT_ROUNDS = 10;

// Configuração CORRETA da conexão com PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { 
        rejectUnauthorized: false 
    } : false
});

// Testar conexão com o banco
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Erro ao conectar com o banco de dados:', err.stack);
    } else {
        console.log('✅ Conexão com o banco de dados estabelecida com sucesso!');
        release();
    }
});

app.get('/', (req, res) => {
    res.send('O servidor back-end do TCC está funcionando!');
});

// Health check para o Render
app.get('/health', async (req, res) => {
  try {
    // Testar conexão com o banco - USANDO pool.query AGORA
    await pool.query('SELECT 1');
    res.status(200).json({ 
      status: 'OK', 
      database: 'Connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({ 
      status: 'Error', 
      database: 'Disconnected',
      error: error.message 
    });
  }
});

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Garante que a pasta uploads existe
        if (!fs.existsSync('uploads')) {
            fs.mkdirSync('uploads', { recursive: true });
        }
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const mime = file.mimetype;

    if (ext === '.pdf' && mime === 'application/pdf') {
        cb(null, true);
    } else {
        cb(new Error('Apenas arquivos PDF são permitidos.'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 1024 * 1024 * 30 // Limite de 30MB
    }
});

app.listen(porta, () => {
    console.log("O servidor está rodando na porta " + porta);
});

// --- Início das rotas ---

function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ mensagem: 'Acesso não autorizado: Token não fornecido.' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('Erro de verificação de token:', err);
            return res.status(401).json({ mensagem: 'Acesso não autorizado: Token inválido.' });
        }
        req.usuario = decoded;
        next();
    });
}

// Rota para cadastrar um novo usuário - CORRIGIDA (usando pool)
app.post('/cadastrar_usuario', async (req, res) => {
    const { nome, email, senha, tipo, curso_id, matricula } = req.body;
    if (!nome || !email || !senha || !tipo) {
        return res.status(400).json({ mensagem: 'Todos os campos obrigatórios devem ser preenchidos.' });
    }
    try {
        const senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);
        const checkSql = 'SELECT * FROM usuarios WHERE email = $1';
        const checkResult = await pool.query(checkSql, [email]); // pool.query agora
        
        if (checkResult.rows.length > 0) {
            return res.status(409).json({ mensagem: 'Usuário com este email já existe.' });
        }
        const sql = 'INSERT INTO usuarios (nome, email, senha, tipo, curso_id, matricula) VALUES ($1, $2, $3, $4, $5, $6)';
        await pool.query(sql, [nome, email, senhaHash, tipo, curso_id, matricula]); // pool.query agora

        res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso!' });
    } catch (err) {
        console.error('Erro ao cadastrar usuário:', err);
        res.status(500).json({ mensagem: 'Erro interno do servidor.' });
    }
});

// Rota de login - CORRIGIDA (usando pool)
app.post('/login', async (req, res) => {
    const { email, senha } = req.body;
    if (!email || !senha) {
        return res.status(400).json({ erro: 'Email e senha são obrigatórios.' });
    }
    try {
        const sql = 'SELECT * FROM usuarios WHERE email = $1';
        const resultados = await pool.query(sql, [email]); // pool.query agora

        if (resultados.rows.length === 0) {
            return res.status(401).json({ erro: 'Email ou senha incorretos.' });
        }
        const usuario = resultados.rows[0];
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha);

        if (!senhaCorreta) {
            return res.status(401).json({ erro: 'Email ou senha incorretos.' });
        }
        const token = jwt.sign(
            { id: usuario.id, tipo: usuario.tipo, email: usuario.email },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
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
        return res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
});

// Todas as outras rotas também precisam usar pool.query em vez de conexao.query
// Vou mostrar algumas, mas você precisa atualizar TODAS:

app.delete('/excluir_usuario/:id', async (req, res) => {
    const { id } = req.params;
    if (!id) return res.status(400).json({ mensagem: "ID do usuário é obrigatório" });
    try {
        const resultado = await pool.query(`DELETE FROM usuarios WHERE id = $1`, [id]); // pool.query agora
        if (resultado.rowCount === 0) return res.status(404).json({ mensagem: "Usuário não encontrado" });
        res.json({ mensagem: "Usuário deletado com sucesso" });
    } catch (error) {
        console.error("Erro ao deletar usuário:", error);
        res.status(500).json({ mensagem: "Erro ao deletar usuário" });
    }
});

app.get('/listar_usuarios', async (req, res) => {
    try {
        const sql = `
            SELECT 
                usuarios.id, 
                usuarios.nome, 
                usuarios.email, 
                CASE 
                    WHEN usuarios.tipo = 'administrador' THEN 'admin'
                    ELSE usuarios.tipo
                END as tipo,
                CASE 
                    WHEN usuarios.tipo = 'aluno' THEN cursos.curso
                    ELSE NULL
                END AS curso
            FROM usuarios
            LEFT JOIN cursos ON usuarios.curso_id = cursos.id
        `;
        const resultados = await pool.query(sql); // pool.query agora
        res.json(resultados.rows);
    } catch (err) {
        console.error("Erro ao listar usuários:", err);
        res.status(500).json({ erro: 'Erro ao listar usuários' });
    }
});

// CONTINUE TROCANDO TODAS AS conexao.query POR pool.query NAS DEMAIS ROTAS...

app.get('/visualizar_tcc/:filename', (req, res) => {
    const { filename } = req.params;
    const filePath = path.join(__dirname, 'uploads', filename);
    if (fs.existsSync(filePath)) {
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
        fs.createReadStream(filePath).pipe(res);
    } else {
        res.status(404).json({ erro: 'Arquivo não encontrado' });
    }
});

// Middleware para tratamento de erros
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    mensagem: 'Erro interno do servidor',
    erro: process.env.NODE_ENV === 'development' ? err.message : 'Ocorreu um erro'
  });
});

// Rota para caso não encontre nenhuma rota
app.use('*', (req, res) => {
  res.status(404).json({ mensagem: 'Rota não encontrada' });
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
