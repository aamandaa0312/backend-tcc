require('dotenv').config();
const express = require('express');
const { Pool } = require('pg'); // Importar Pool do 'pg'
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const bcryptjs = require('bcryptjs');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const jwt = require ('jsonwebtoken');

const porta = process.env.PORT || 3000;
const app = express();
app.use(express.json());

const JWT_SECRET = 'seu_segredo_jwt';
const SALT_ROUNDS = 10; // Custo do hash para bcrypt

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

// Configuração do Pool de Conexões PostgreSQL
const pool = new Pool({
    user: process.env.DB_USER || "db_tcc_jygq_user",
    host: process.env.DB_HOST || "dpg-d2kcc6ggjchc73dnnpng-a.oregon-postgres.render.com",
    database: process.env.DB_DATABASE || "db_tcc_jygq",
    password: process.env.DB_PASSWORD || "D9r1tKKtkH5NzSihsq0S5YUFdigyEIrM",
    port: process.env.DB_PORT || 5432,
    ssl: {
        rejectUnauthorized: false // Necessário para alguns provedores de hospedagem como Render
    }
});
//inicio rotas usuario
//Middleware para verificar a conexão com o banco de dados
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
   // Rota para cadastrar um novo usuário
   app.post('/cadastrar_usuario', async (req, res) => {
    const { nome, email, senha, tipo, curso_id, matricula } = req.body;
  
    if (!nome || !email || !senha || !tipo) {
      return res.status(400).json({ mensagem: 'Todos os campos obrigatórios devem ser preenchidos.' });
    }
  
    try {
      const senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);
  
      // Verificar se o usuário já existe
      const checkSql = 'SELECT * FROM usuarios WHERE email = $1';
      const checkResult = await pool.query(checkSql, [email]);
  
      if (checkResult.rows.length > 0) {
        return res.status(409).json({ mensagem: 'Usuário com este email já existe.' });
      }
  
      // Inserir novo usuário
      const insertSql = `
        INSERT INTO usuarios (nome, email, senha, tipo, curso_id, matricula)
        VALUES ($1, $2, $3, $4, $5, $6)
      `;
      await pool.query(insertSql, [nome, email, senhaHash, tipo, curso_id, matricula]);
  
      res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso!' });
  
    } catch (err) {
      console.error('Erro ao cadastrar usuário:', err);
      res.status(500).json({ mensagem: 'Erro interno do servidor.' });
    }
  });

  app.post('/login', async (req, res) => {
    const { email, senha } = req.body;
  
    if (!email || !senha) {
      return res.status(400).json({ erro: 'Email e senha são obrigatórios.' });
    }
  
    try {
      const sql = 'SELECT * FROM usuarios WHERE email = $1';
      const result = await pool.query(sql, [email]);
  
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
  
      res.status(200).json({
        mensagem: 'Login bem-sucedido!',
        token,
        usuario: {
          id: usuario.id,
          nome: usuario.nome,
          email: usuario.email,
          tipo: usuario.tipo,
        },
      });
  
    } catch (err) {
      console.error('Erro ao buscar usuário:', err);
      res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
  });
  
  
  
// Testar a conexão com o banco de dados
pool.on('connect', () => {
    console.log('Conectado ao banco de dados PostgreSQL');
});

pool.on('error', (err) => {
    console.error('Erro inesperado no pool do PostgreSQL:', err);
    process.exit(-1); // Encerrar a aplicação em caso de erro crítico no pool
});

app.listen(porta, () => {
    console.log(`O servidor está rodando na porta ${porta}`);
});

// Rota para cadastrar um novo usuário
app.post('/cadastrar_usuario', async (req, res) => {
    const { nome, email, senha, tipo, curso_id } = req.body;

    if (!nome || !email || !senha || !tipo) {
        return res.status(400).json({ mensagem: 'Todos os campos obrigatórios devem ser preenchidos.' });
    }

    try {
        const senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);

        const checkSql = 'SELECT * FROM usuarios WHERE email = $1';
        const checkResult = await pool.query(checkSql, [email]);

        if (checkResult.rows.length > 0) {
            return res.status(409).json({ mensagem: 'Usuário com este email já existe.' });
        }

        const sql = 'INSERT INTO usuarios (nome, email, senha, tipo, curso_id) VALUES ($1, $2, $3, $4, $5)';
        await pool.query(sql, [nome, email, senhaHash, tipo, curso_id]);

        res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso!' });
    } catch (err) {
        console.error('Erro ao cadastrar usuário:', err);
        res.status(500).json({ mensagem: 'Erro interno do servidor.' });
    }
});

app.post('/login', async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ erro: 'Email e senha são obrigatórios.' });
    }

    try {
        const sql = 'SELECT * FROM usuarios WHERE email = $1';
        const result = await pool.query(sql, [email]);

        if (result.rows.length === 0) {
            return res.status(401).json({ erro: 'Email ou senha incorretos.' });
        }

        const usuario = result.rows[0];

        const senhaCorreta = await bcrypt.compare(senha, usuario.senha);

        if (!senhaCorreta) {
            return res.status(401).json({ erro: 'Email ou senha incorretos.' });
        }

        res.status(200).json({
            mensagem: 'Login bem-sucedido!',
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                tipo: usuario.tipo
            }
        });
    } catch (err) {
        console.error('Erro ao buscar usuário ou comparar senha:', err);
        res.status(500).json({ erro: 'Erro interno do servidor durante a autenticação.' });
    }
});

app.delete('/excluir_usuario/:id', async (req, res) => {
    const { id } = req.params;

    if (!id) {
        return res.status(400).json({ mensagem: "ID do usuário é obrigatório" });
    }

    try {
        const sql = `DELETE FROM usuarios WHERE id = $1`;
        const result = await pool.query(sql, [id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ mensagem: "Usuário não encontrado" });
        }
        res.json({ mensagem: "Usuário deletado com sucesso" });
    } catch (error) {
        console.error("Erro ao deletar usuário:", error);
        res.status(500).json({ mensagem: "Erro ao deletar usuário" });
    }
});

app.get('/listar_usuarios', async (req, res) => {
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
    `; // Usar CASE WHEN para simular IF no PostgreSQL

    try {
        const result = await pool.query(sql);
        res.json(result.rows);
    } catch (err) {
        console.error("Erro ao listar usuários:", err);
        res.status(500).json({ erro: 'Erro ao listar usuários' });
    }
});

app.put('/editar_usuario', async (req, res) => {
    const { id, nome, email, tipo, curso_id } = req.body;

    console.log("Dados recebidos para edição:", req.body);
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

        const result = await pool.query(sql, params);

        if (result.rowCount === 0) {
            return res.status(404).json({ mensagem: "Usuário não encontrado" });
        }
        res.json({ mensagem: "Usuário atualizado com sucesso" });
    } catch (error) {
        console.error("Erro ao editar usuário:", error);
        res.status(500).json({ mensagem: "Erro ao editar usuário" });
    }
});

app.get('/perfil', async (req, res) => {
    // Assumindo que req.usuario.id é definido por um middleware de autenticação
    // que você pode precisar implementar. Para este exemplo, vamos simular um ID.
    const usuarioId = req.usuario ? req.usuario.id : 1; // Substitua por sua lógica de autenticação real

    try {
        const sql = 'SELECT id, nome, email, tipo FROM usuarios WHERE id = $1';
        const result = await pool.query(sql, [usuarioId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ mensagem: 'Usuário não encontrado.' });
        }

        res.status(200).json(result.rows[0]);
    } catch (err) {
        console.error('Erro ao buscar dados do perfil:', err);
        res.status(500).json({ mensagem: 'Erro interno do servidor.' });
    }
});

// Fim rotas usuario

app.get('/listar_tccs', async (req, res) => {
    const { status } = req.query;

    let sql = 'SELECT tccs.*, cursos.curso FROM tccs JOIN cursos ON tccs.curso_id = cursos.id';
    const params = [];

    if (status) {
        sql += ' WHERE tccs.status = $1';
        params.push(status);
    }

    try {
        const result = await pool.query(sql, params);
        res.json(result.rows);
    } catch (err) {
        console.error('Erro ao listar TCCs:', err);
        res.status(500).json({ erro: 'Erro ao listar TCCs' });
    }
});

// rota para listar tccs por ano
app.get("/listar_tccs_por_ano", async (req, res) => {
    const { ano } = req.query;

    if (!ano) {
        return res.status(400).json({ erro: "O ano é obrigatório!" });
    }

    try {
        const sql = "SELECT * FROM tccs WHERE ano = $1";
        const result = await pool.query(sql, [ano]);

        if (result.rows.length === 0) {
            return res.json({ mensagem: "Nenhum TCC encontrado para este ano." });
        }

        res.json(result.rows);
    } catch (erro) {
        console.error("Erro ao buscar os TCCs:", erro);
        res.status(500).json({ erro: "Erro ao buscar os TCCs." });
    }
});

// tcc e ano
app.get('/tccs', async (req, res) => {
    const { curso_id, ano } = req.query; // Removido 'status' pois é fixo para 'aprovado'

    let sql = `
        SELECT tccs.*, cursos.curso 
        FROM tccs 
        INNER JOIN cursos ON tccs.curso_id = cursos.id
        WHERE tccs.status = $1
    `;

    const params = ['aprovado']; // Filtro fixo para aprovados
    let paramIndex = 2; // Começa em 2 porque $1 já é 'aprovado'

    // Filtros opcionais
    if (curso_id) {
        sql += ` AND cursos.id = $${paramIndex}`;
        params.push(curso_id);
        paramIndex++;
    }
    if (ano) {
        sql += ` AND tccs.ano = $${paramIndex}`;
        params.push(ano);
        paramIndex++;
    }

    sql += ' ORDER BY tccs.ano DESC, tccs.titulo ASC';

    try {
        const result = await pool.query(sql, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar TCCs:', error);
        res.status(500).json({ erro: 'Falha ao filtrar TCCs' });
    }
});

// INICIO ROTAS DE CURSO
// Rota para cadastrar curso
app.post('/cadastrar_curso', async (req, res) => {
    const { curso } = req.body;

    if (!curso || !curso.trim()) {
        return res.status(400).json({ erro: 'O nome do curso é obrigatório' });
    }

    try {
        const sql = 'INSERT INTO cursos (curso) VALUES ($1)';
        await pool.query(sql, [curso]);
        res.json({ mensagem: "Curso cadastrado com sucesso!" });
    } catch (err) {
        console.error('Erro ao cadastrar curso:', err);
        res.status(500).json({ erro: 'Erro ao cadastrar curso' });
    }
});

// Rota para listar cursos
app.get('/listar_cursos', async (req, res) => {
    const sql = 'SELECT id, curso FROM cursos';
    try {
        const result = await pool.query(sql);
        res.json(result.rows);
    } catch (err) {
        console.error('Erro ao listar cursos:', err);
        res.status(500).json({ erro: 'Erro ao listar cursos' });
    }
});

app.delete('/excluir_curso/:id', async (req, res) => {
    const { id } = req.params;

    if (!id) {
        return res.status(400).json({ mensagem: "ID do curso é obrigatório" });
    }

    try {
        const sql = `DELETE FROM cursos WHERE id = $1`;
        const result = await pool.query(sql, [id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ mensagem: "Curso não encontrado" });
        }

        res.json({ mensagem: "Curso deletado com sucesso" });
    } catch (error) {
        console.error("Erro ao deletar curso:", error);
        // PostgreSQL usa códigos de erro diferentes para violações de chave estrangeira
        if (error.code === '23503') { // foreign_key_violation
            return res.status(400).json({ mensagem: "Este curso está vinculado a TCCs e não pode ser excluído." });
        }
        res.status(500).json({ mensagem: "Erro ao deletar curso" });
    }
});

app.put('/editar_curso', async (req, res) => {
    const { id, curso } = req.body;

    if (!id || !curso || !curso.trim()) {
        return res.status(400).json({ mensagem: 'ID e nome do curso são obrigatórios' });
    }

    try {
        const sql = `UPDATE cursos SET curso = $1 WHERE id = $2`;
        const result = await pool.query(sql, [curso, id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Curso não encontrado' });
        }

        res.json({ mensagem: 'Curso atualizado com sucesso!' });
    } catch (err) {
        console.error('Erro ao editar curso:', err);
        res.status(500).json({ mensagem: 'Erro ao editar curso' });
    }
});

// INTRANET (Rota de login duplicada, manter apenas uma ou diferenciar)
// Esta rota de login parece ser para um sistema de intranet com matrícula.
// Se for um sistema separado, considere mover para um arquivo ou prefixo de rota diferente.
// Se for o mesmo sistema, decida qual método de login (email ou matrícula) será o principal.
app.post('/login_intranet', async (req, res) => { // Renomeada para evitar conflito
    const { matricula, senha } = req.body;

    if (!matricula || !senha) {
        return res.status(400).json({ erro: 'Matrícula e senha são obrigatórios.' });
    }

    try {
        const sql = 'SELECT * FROM usuarios WHERE matricula = $1';
        const result = await pool.query(sql, [matricula]);

        if (result.rows.length === 0) {
            return res.status(401).json({ erro: 'Matrícula ou senha incorretos.' });
        }

        const usuario = result.rows[0];

        // Assumindo que 'senha_hash' é o nome da coluna no banco de dados para a senha hasheada
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha_hash);

        if (!senhaCorreta) {
            return res.status(401).json({ erro: 'Matrícula ou senha incorretos.' });
        }

        res.status(200).json({
            mensagem: 'Login bem-sucedido!',
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                tipo: usuario.tipo
            }
        });
    } catch (err) {
        console.error('Erro ao buscar usuário ou comparar senha (intranet):', err);
        res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
});

// Rota para visualizar o arquivo do TCC
app.get('/visualizar_tcc/:filename', (req, res) => {
    const { filename } = req.params;
    const filePath = path.join(__dirname, 'uploads', filename);

    console.log('Tentando acessar arquivo:', filePath);

    if (fs.existsSync(filePath)) {
        console.log('Arquivo encontrado, enviando...');
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
        fs.createReadStream(filePath).pipe(res);
    } else {
        console.log('Arquivo não encontrado');
        res.status(404).json({ erro: 'Arquivo não encontrado' });
    }
});

app.post('/upload_tcc', upload.single('arquivo'), async (req, res) => {
    console.log('Corpo da requisição:', req.body);
    console.log('Arquivo recebido:', req.file);

    const { titulo, ano, autor, curso } = req.body;
    const arquivo = req.file;

    if (!titulo || !ano || !autor || !curso || !arquivo) {
        if (arquivo && fs.existsSync(arquivo.path)) {
            fs.unlinkSync(arquivo.path);
        }
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios' });
    }

    const extensao = path.extname(arquivo.originalname).toLowerCase();
    if (extensao !== '.pdf') {
        fs.unlinkSync(arquivo.path);
        return res.status(400).json({ erro: 'Apenas arquivos PDF são permitidos' });
    }

    try {
        const sqlCurso = 'SELECT id FROM cursos WHERE id = $1';
        const resultCurso = await pool.query(sqlCurso, [curso]);

        if (resultCurso.rows.length === 0) {
            fs.unlinkSync(arquivo.path);
            return res.status(400).json({ erro: 'Curso não encontrado' });
        }

        const cursoId = resultCurso.rows[0].id;
        const sql = 'INSERT INTO tccs (titulo, ano, autor, curso_id, arquivo, status) VALUES ($1, $2, $3, $4, $5, $6)';

        await pool.query(sql, [titulo, ano, autor, cursoId, arquivo.filename, 'pendente']);
        res.json({ mensagem: 'TCC cadastrado com sucesso!' });
    } catch (err) {
        console.error('Erro ao inserir no banco ou verificar curso:', err);
        if (arquivo && fs.existsSync(arquivo.path)) {
            fs.unlinkSync(arquivo.path);
        }
        res.status(500).json({ erro: 'Erro ao salvar TCC no banco de dados', detalhes: err.message });
    }
});

// Rota para aprovar/rejeitar TCC
app.post('/avaliar_tcc', async (req, res) => {
    const { id, status, comentario } = req.body;

    if (!id || isNaN(id)) {
        return res.status(400).json({ erro: 'ID do TCC inválido' });
    }

    if (!['aprovado', 'rejeitado'].includes(status)) {
        return res.status(400).json({ erro: 'Status inválido. Deve ser "aprovado" ou "rejeitado"' });
    }

    try {
        const checkSql = 'SELECT * FROM tccs WHERE id = $1';
        const checkResult = await pool.query(checkSql, [id]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ erro: 'TCC não encontrado' });
        }

        const updateSql = 'UPDATE tccs SET status = $1, comentario = $2, avaliado_em = NOW() WHERE id = $3';
        await pool.query(updateSql, [status, comentario || null, id]);

        res.json({
            mensagem: `TCC ${status} com sucesso!`,
            dados: {
                id,
                status,
                comentario
            }
        });
    } catch (err) {
        console.error('Erro ao avaliar TCC:', err);
        res.status(500).json({ erro: 'Erro ao avaliar TCC' });
    }
});

app.delete('/excluir_tcc/:id', async (req, res) => {
    const { id } = req.params;

    if (!id) {
        return res.status(400).json({ mensagem: "ID do TCC é obrigatório" });
    }

    try {
        const sql = `DELETE FROM tccs WHERE id = $1`;
        const result = await pool.query(sql, [id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ mensagem: "TCC não encontrado" });
        }
        res.json({ mensagem: "TCC deletado com sucesso" });
    } catch (error) {
        console.error("Erro ao deletar TCC:", error);
        res.status(500).json({ mensagem: "Erro ao deletar TCC" });
    }
});

app.put('/editar_tcc', async (req, res) => {
    const { id, titulo, ano, autor, curso_id } = req.body;

    if (!id || !titulo || !ano || !autor || !curso_id) {
        return res.status(400).json({ mensagem: 'Todos os campos são obrigatórios' });
    }

    try {
        const sql = `UPDATE tccs SET titulo = $1, ano = $2, autor = $3, curso_id = $4 WHERE id = $5`;
        const result = await pool.query(sql, [titulo, ano, autor, curso_id, id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ mensagem: 'TCC não encontrado' });
        }

        res.json({ mensagem: 'TCC atualizado com sucesso!' });
    } catch (err) {
        console.error('Erro ao editar TCC:', err);
        res.status(500).json({ mensagem: 'Erro ao editar TCC' });
    }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
