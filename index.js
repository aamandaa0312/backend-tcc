require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bcryptjs = require('bcryptjs');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const porta = process.env.PORT || 3000;
const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 10;

app.get('/', (req, res) => {
    res.send('O servidor back-end do TCC está funcionando!');
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

// A conexão agora usa a variável de ambiente do Render
const conexao = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
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

// Rota para cadastrar um novo usuário (refatorada para PostgreSQL)
app.post('/cadastrar_usuario', async (req, res) => {
    const { nome, email, senha, tipo, curso_id, matricula } = req.body;
    if (!nome || !email || !senha || !tipo) {
        return res.status(400).json({ mensagem: 'Todos os campos obrigatórios devem ser preenchidos.' });
    }
    try {
        const senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);
        const checkSql = 'SELECT * FROM usuarios WHERE email = $1';
        const checkResult = await conexao.query(checkSql, [email]);
        
        if (checkResult.rowCount > 0) {
            return res.status(409).json({ mensagem: 'Usuário com este email já existe.' });
        }
        const sql = 'INSERT INTO usuarios (nome, email, senha, tipo, curso_id, matricula) VALUES ($1, $2, $3, $4, $5, $6)';
        await conexao.query(sql, [nome, email, senhaHash, tipo, curso_id, matricula]);

        res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso!' });
    } catch (err) {
        console.error('Erro ao cadastrar usuário:', err);
        res.status(500).json({ mensagem: 'Erro interno do servidor.' });
    }
});

// Rota de login (refatorada para PostgreSQL)
app.post('/login', async (req, res) => {
    const { email, senha } = req.body;
    if (!email || !senha) {
        return res.status(400).json({ erro: 'Email e senha são obrigatórios.' });
    }
    try {
        const sql = 'SELECT * FROM usuarios WHERE email = $1';
        const resultados = await conexao.query(sql, [email]);

        if (resultados.rowCount === 0) {
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

app.delete('/excluir_usuario/:id', async (req, res) => {
    const { id } = req.params;
    if (!id) return res.status(400).json({ mensagem: "ID do usuário é obrigatório" });
    try {
        const resultado = await conexao.query(`DELETE FROM usuarios WHERE id = $1`, [id]);
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
        const resultados = await conexao.query(sql);
        res.json(resultados.rows);
    } catch (err) {
        console.error("Erro ao listar usuários:", err);
        res.status(500).json({ erro: 'Erro ao listar usuários' });
    }
});

app.put('/editar_usuario', async (req, res) => {
    const { id, nome, email, tipo, curso_id } = req.body;
    if (!id || !nome?.trim() || !email?.trim() || !tipo?.trim()) {
        return res.status(400).json({ mensagem: "Preencha todos os campos obrigatórios" });
    }
    const tipoNormalizado = tipo === 'admin' ? 'administrador' : tipo;
    const cursoIdTratado = curso_id === '' ? null : curso_id;
    try {
        let sql;
        let params;
        if (tipoNormalizado === 'aluno') {
            sql = `UPDATE usuarios SET nome = $1, email = $2, tipo = $3, curso_id = $4 WHERE id = $5`;
            params = [nome, email, tipoNormalizado, cursoIdTratado, id];
        } else {
            sql = `UPDATE usuarios SET nome = $1, email = $2, tipo = $3, curso_id = NULL WHERE id = $4`;
            params = [nome, email, tipoNormalizado, id];
        }
        const resultado = await conexao.query(sql, params);
        if (resultado.rowCount === 0) return res.status(404).json({ mensagem: "Usuário não encontrado" });
        res.json({ mensagem: "Usuário atualizado com sucesso" });
    } catch (error) {
        console.error("Erro ao editar usuário:", error);
        res.status(500).json({ mensagem: "Erro ao editar usuário" });
    }
});

app.get('/perfil', verificarToken, async (req, res) => {
    const usuarioId = req.usuario.id;
    try {
        const sql = 'SELECT id, nome, email, tipo FROM usuarios WHERE id = $1';
        const resultados = await conexao.query(sql, [usuarioId]);
        if (resultados.rowCount === 0) return res.status(404).json({ mensagem: 'Usuário não encontrado.' });
        res.status(200).json(resultados.rows[0]);
    } catch (err) {
        console.error('Erro ao buscar dados do perfil:', err);
        res.status(500).json({ mensagem: 'Erro interno do servidor.' });
    }
});

app.get('/listar_tccs', async (req, res) => {
    const { status } = req.query;
    let sql = 'SELECT tccs.*, cursos.curso FROM tccs JOIN cursos ON tccs.curso_id = cursos.id';
    const params = [];
    if (status) {
        sql += ' WHERE tccs.status = $1';
        params.push(status);
    }
    try {
        const resultados = await conexao.query(sql, params);
        res.json(resultados.rows);
    } catch (err) {
        console.error("Erro ao listar TCCs:", err);
        res.status(500).json({ erro: 'Erro ao listar TCCs' });
    }
});

app.get("/listar_tccs_por_ano", async (req, res) => {
    const { ano } = req.query;
    if (!ano) return res.status(400).json({ erro: "O ano é obrigatório!" });
    try {
        const tccs = await conexao.query("SELECT * FROM tccs WHERE ano = $1", [ano]);
        if (tccs.rowCount === 0) return res.json({ mensagem: "Nenhum TCC encontrado para este ano." });
        res.json(tccs.rows);
    } catch (erro) {
        console.error("Erro ao buscar os TCCs:", erro);
        res.status(500).json({ erro: "Erro ao buscar os TCCs." });
    }
});

app.get('/tccs', async (req, res) => {
    const { curso_id, ano, status } = req.query;
    let sql = `
        SELECT tccs.*, cursos.curso 
        FROM tccs 
        INNER JOIN cursos ON tccs.curso_id = cursos.id
        WHERE tccs.status = $1
    `;
    const params = ['aprovado'];
    if (curso_id) {
        sql += ' AND cursos.id = $2';
        params.push(curso_id);
    }
    if (ano) {
        sql += ' AND tccs.ano = $3';
        params.push(ano);
    }
    sql += ' ORDER BY tccs.ano DESC, tccs.titulo ASC';
    try {
        const resultados = await conexao.query(sql, params);
        res.json(resultados.rows);
    } catch (error) {
        console.error('Erro ao buscar TCCs:', error);
        res.status(500).json({ erro: 'Falha ao filtrar TCCs' });
    }
});

// INICIO ROTAS DE CURSO
app.post('/cadastrar_curso', async (req, res) => {
    const { curso } = req.body;
    if (!curso || !curso.trim()) return res.status(400).json({ erro: 'O nome do curso é obrigatório' });
    try {
        const sql = 'INSERT INTO cursos (curso) VALUES ($1)';
        await conexao.query(sql, [curso]);
        res.json({ mensagem: "Curso cadastrado com sucesso!" });
    } catch (err) {
        console.error('Erro ao cadastrar curso:', err);
        res.status(500).json({ erro: 'Erro ao cadastrar curso' });
    }
});

app.get('/listar_cursos', async (req, res) => {
    try {
        const sql = 'SELECT id, curso FROM cursos';
        const resultados = await conexao.query(sql);
        res.json(resultados.rows);
    } catch (err) {
        console.error('Erro ao listar cursos:', err);
        res.status(500).json({ erro: 'Erro ao listar cursos' });
    }
});

app.delete('/excluir_curso/:id', async (req, res) => {
    const { id } = req.params;
    if (!id) return res.status(400).json({ mensagem: "ID do curso é obrigatório" });
    const sql = `DELETE FROM cursos WHERE id = $1`;
    try {
        const resultado = await conexao.query(sql, [id]);
        if (resultado.rowCount === 0) return res.status(404).json({ mensagem: "Curso não encontrado" });
        res.json({ mensagem: "Curso deletado com sucesso" });
    } catch (error) {
        console.error("Erro ao deletar curso:", error);
        res.status(500).json({ mensagem: "Erro ao deletar curso" });
    }
});

app.put('/editar_curso', async (req, res) => {
    const { id, curso } = req.body;
    if (!id || !curso || !curso.trim()) return res.status(400).json({ mensagem: 'ID e nome do curso são obrigatórios' });
    const sql = `UPDATE cursos SET curso = $1 WHERE id = $2`;
    try {
        const resultado = await conexao.query(sql, [curso, id]);
        if (resultado.rowCount === 0) return res.status(404).json({ mensagem: 'Curso não encontrado' });
        res.json({ mensagem: 'Curso atualizado com sucesso!' });
    } catch (err) {
        console.error('Erro ao editar curso:', err);
        res.status(500).json({ mensagem: 'Erro ao editar curso' });
    }
});

// INTRANET (ajustado para PostgreSQL)
app.post('/intranet/login', async (req, res) => {
    const { matricula, senha } = req.body;
    if (!matricula || !senha) {
        return res.status(400).json({ erro: 'Matrícula e senha são obrigatórios.' });
    }
    try {
        const sql = 'SELECT * FROM usuarios WHERE matricula = $1';
        const resultados = await conexao.query(sql, [matricula]);
        if (resultados.rowCount === 0) return res.status(401).json({ erro: 'Matrícula ou senha incorretos.' });
        const usuario = resultados.rows[0];
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha_hash);
        if (!senhaCorreta) return res.status(401).json({ erro: 'Matrícula ou senha incorretos.' });
        const token = jwt.sign(
            { id: usuario.id, tipo: usuario.tipo },
            process.env.JWT_SECRET,
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
    } catch (error) {
        console.error('Erro no login da intranet:', error);
        res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
});

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

app.post('/upload_tcc', upload.single('arquivo'), async (req, res) => {
    const { titulo, ano, autor, curso } = req.body;
    const arquivo = req.file;
    if (!titulo || !ano || !autor || !curso || !arquivo) {
        if (arquivo && fs.existsSync(arquivo.path)) fs.unlinkSync(arquivo.path);
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios' });
    }
    const extensao = path.extname(arquivo.originalname).toLowerCase();
    if (extensao !== '.pdf') {
        fs.unlinkSync(arquivo.path);
        return res.status(400).json({ erro: 'Apenas arquivos PDF são permitidos' });
    }
    try {
        const sqlCurso = 'SELECT id FROM cursos WHERE id = $1';
        const resultCurso = await conexao.query(sqlCurso, [curso]);
        if (resultCurso.rowCount === 0) {
            fs.unlinkSync(arquivo.path);
            return res.status(400).json({ erro: 'Curso não encontrado' });
        }
        const cursoId = resultCurso.rows[0].id;
        const sql = 'INSERT INTO tccs (titulo, ano, autor, curso_id, arquivo, status) VALUES ($1, $2, $3, $4, $5, $6)';
        await conexao.query(sql, [titulo, ano, autor, cursoId, arquivo.filename, 'pendente']);
        res.json({ mensagem: 'TCC cadastrado com sucesso!' });
    } catch (err) {
        console.error('Erro ao inserir no banco:', err);
        if (arquivo && fs.existsSync(arquivo.path)) fs.unlinkSync(arquivo.path);
        res.status(500).json({ erro: 'Erro ao salvar TCC no banco de dados', detalhes: err.message });
    }
});

app.post('/avaliar_tcc', async (req, res) => {
    const { id, status, comentario } = req.body;
    if (!id || isNaN(id)) return res.status(400).json({ erro: 'ID do TCC inválido' });
    if (!['aprovado', 'rejeitado'].includes(status)) return res.status(400).json({ erro: 'Status inválido. Deve ser "aprovado" ou "rejeitado"' });
    try {
        const checkSql = 'SELECT * FROM tccs WHERE id = $1';
        const results = await conexao.query(checkSql, [id]);
        if (results.rowCount === 0) return res.status(404).json({ erro: 'TCC não encontrado' });
        const updateSql = 'UPDATE tccs SET status = $1, comentario = $2, avaliado_em = NOW() WHERE id = $3';
        await conexao.query(updateSql, [status, comentario || null, id]);
        res.json({
            mensagem: `TCC ${status} com sucesso!`,
            dados: { id, status, comentario }
        });
    } catch (err) {
        console.error('Erro ao atualizar TCC:', err);
        res.status(500).json({ erro: 'Erro ao atualizar TCC' });
    }
});

app.delete('/excluir_tcc/:id', async (req, res) => {
    const { id } = req.params;
    if (!id) return res.status(400).json({ mensagem: "ID do TCC é obrigatório" });
    const sql = `DELETE FROM tccs WHERE id = $1`;
    try {
        const resultado = await conexao.query(sql, [id]);
        if (resultado.rowCount === 0) return res.status(404).json({ mensagem: "TCC não encontrado" });
        res.json({ mensagem: "TCC deletado com sucesso" });
    } catch (error) {
        console.error("Erro ao deletar TCC:", error);
        res.status(500).json({ mensagem: "Erro ao deletar TCC" });
    }
});

app.put('/editar_tcc', async (req, res) => {
    const { id, titulo, ano, autor, curso_id } = req.body;
    if (!id || !titulo || !ano || !autor || !curso_id) return res.status(400).json({ mensagem: 'Todos os campos são obrigatórios' });
    const sql = `UPDATE tccs SET titulo = $1, ano = $2, autor = $3, curso_id = $4 WHERE id = $5`;
    try {
        const resultado = await conexao.query(sql, [titulo, ano, autor, curso_id, id]);
        if (resultado.rowCount === 0) return res.status(404).json({ mensagem: 'TCC não encontrado' });
        res.json({ mensagem: 'TCC atualizado com sucesso!' });
    } catch (err) {
        console.error('Erro ao editar TCC:', err);
        res.status(500).json({ mensagem: 'Erro ao editar TCC' });
    }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

