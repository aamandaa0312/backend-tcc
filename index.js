require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto'); // Não utilizado no código fornecido, mas mantido
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bcryptjs = require('bcryptjs'); // Não utilizado no código fornecido, mas mantido
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const porta = process.env.PORT || 5432; // Render geralmente define a porta automaticamente
const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 10;

// Middleware CORS
app.use(cors({
    origin: '*', // Permite todas as origens. Em produção, considere restringir.
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middlewares para parsing do corpo da requisição
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuração do Multer para upload de arquivos
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Cria o diretório 'uploads' se não existir
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
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

// Configuração da conexão com o PostgreSQL
const conexao = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Necessário para Render e outros serviços com certificados autoassinados
    }
});

// Testar a conexão com o banco de dados antes de iniciar o servidor
conexao.connect()
    .then(() => {
        console.log("Conexão com o banco de dados estabelecida com sucesso!");
        // Inicia o servidor Express somente após a conexão bem-sucedida
        app.listen(porta, () => {
            console.log("O servidor está rodando na porta " + porta);
        });
    })
    .catch(err => {
        console.error("Erro ao conectar ao banco de dados:", err.message);
        console.error("Verifique se DATABASE_URL está configurada corretamente e se o banco de dados está acessível.");
        process.exit(1); // Encerra o processo se a conexão com o DB falhar
    });

// --- Início das rotas ---

// Rota de teste
app.get('/', (req, res) => {
    res.send('O servidor back-end do TCC está funcionando!');
});

// Middleware para verificar token JWT
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

// Rota de login
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

// Rota para excluir usuário
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

// Rota para listar usuários
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

// Rota para editar usuário
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

// Rota para perfil do usuário (requer token)
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

// Rota para listar TCCs (com filtro opcional por status)
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

// Rota para listar TCCs por ano
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

// Rota para filtrar TCCs (aprovados, por curso e ano)
app.get('/tccs', async (req, res) => {
    const { curso_id, ano } = req.query; // Removido 'status' pois a query já filtra por 'aprovado'
    let sql = `
        SELECT tccs.*, cursos.curso 
        FROM tccs 
        INNER JOIN cursos ON tccs.curso_id = cursos.id
        WHERE tccs.status = $1
    `;
    const params = ['aprovado'];
    let paramIndex = 2; // Começa em 2 porque $1 já é 'aprovado'

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
        const resultados = await conexao.query(sql, params);
        res.json(resultados.rows);
    } catch (error) {
        console.error('Erro ao buscar TCCs:', error);
        res.status(500).json({ erro: 'Falha ao filtrar TCCs' });
    }
});

// --- ROTAS DE CURSO ---

// Rota para cadastrar um novo curso
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

// Rota para listar cursos
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

// Rota para excluir curso
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

// Rota para editar curso
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

// --- ROTAS DA INTRANET ---

// Rota de login da intranet (usando matrícula)
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
        // Assumindo que 'senha_hash' é o campo correto para a senha na intranet
        // Se for 'senha' como no login principal, ajuste aqui.
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha_hash || usuario.senha); 
        if (!senhaCorreta) return res.status(401).json({ erro: 'Matrícula ou senha incorretos.' });
        const token = jwt.sign(
            { id: usuario.id, tipo: usuario.tipo },
            JWT_SECRET, // Usar JWT_SECRET definido globalmente
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

// Rota para visualizar TCC (servir arquivo PDF)
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

// Rota para upload de TCC
app.post('/upload_tcc', upload.single('arquivo'), async (req, res) => {
    const { titulo, ano, autor, curso } = req.body;
    const arquivo = req.file;

    // Verifica se todos os campos obrigatórios e o arquivo foram fornecidos
    if (!titulo || !ano || !autor || !curso || !arquivo) {
        // Se o arquivo foi enviado mas faltam campos, remove o arquivo
        if (arquivo && fs.existsSync(arquivo.path)) {
            fs.unlinkSync(arquivo.path);
        }
        return res.status(400).json({ erro: 'Todos os campos (título, ano, autor, curso) e o arquivo são obrigatórios.' });
    }

    // A validação de extensão já é feita pelo `fileFilter` do multer, mas é bom ter uma redundância
    const extensao = path.extname(arquivo.originalname).toLowerCase();
    if (extensao !== '.pdf') {
        fs.unlinkSync(arquivo.path); // Remove o arquivo se a extensão for inválida
        return res.status(400).json({ erro: 'Apenas arquivos PDF são permitidos.' });
    }

    try {
        // Verifica se o curso_id fornecido existe
        const sqlCurso = 'SELECT id FROM cursos WHERE id = $1';
        const resultCurso = await conexao.query(sqlCurso, [curso]);
        if (resultCurso.rowCount === 0) {
            fs.unlinkSync(arquivo.path); // Remove o arquivo se o curso não for encontrado
            return res.status(400).json({ erro: 'Curso não encontrado.' });
        }
        const cursoId = resultCurso.rows[0].id;

        // Insere os dados do TCC no banco de dados
        const sql = 'INSERT INTO tccs (titulo, ano, autor, curso_id, arquivo, status) VALUES ($1, $2, $3, $4, $5, $6)';
        await conexao.query(sql, [titulo, ano, autor, cursoId, arquivo.filename, 'pendente']);
        
        res.json({ mensagem: 'TCC cadastrado com sucesso e aguardando avaliação!' });
    } catch (err) {
        console.error('Erro ao inserir TCC no banco de dados:', err);
        // Em caso de erro no DB, remove o arquivo que foi salvo
        if (arquivo && fs.existsSync(arquivo.path)) {
            fs.unlinkSync(arquivo.path);
        }
        res.status(500).json({ erro: 'Erro ao salvar TCC no banco de dados', detalhes: err.message });
    }
});

// Rota para avaliar TCC (aprovar/rejeitar)
app.post('/avaliar_tcc', async (req, res) => {
    const { id, status, comentario } = req.body;
    if (!id || isNaN(id)) return res.status(400).json({ erro: 'ID do TCC inválido.' });
    if (!['aprovado', 'rejeitado'].includes(status)) return res.status(400).json({ erro: 'Status inválido. Deve ser "aprovado" ou "rejeitado".' });
    try {
        const checkSql = 'SELECT * FROM tccs WHERE id = $1';
        const results = await conexao.query(checkSql, [id]);
        if (results.rowCount === 0) return res.status(404).json({ erro: 'TCC não encontrado.' });
        const updateSql = 'UPDATE tccs SET status = $1, comentario = $2, avaliado_em = NOW() WHERE id = $3';
        await conexao.query(updateSql, [status, comentario || null, id]);
        res.json({
            mensagem: `TCC ${status} com sucesso!`,
            dados: { id, status, comentario }
        });
    } catch (err) {
        console.error('Erro ao atualizar TCC:', err);
        res.status(500).json({ erro: 'Erro ao atualizar TCC.' });
    }
});

// Rota para excluir TCC
app.delete('/excluir_tcc/:id', async (req, res) => {
    const { id } = req.params;
    if (!id) return res.status(400).json({ mensagem: "ID do TCC é obrigatório." });
    
    try {
        // Opcional: Obter o nome do arquivo antes de deletar o registro do DB para poder excluí-lo do sistema de arquivos
        const getFileSql = 'SELECT arquivo FROM tccs WHERE id = $1';
        const fileResult = await conexao.query(getFileSql, [id]);
        let filenameToDelete = null;
        if (fileResult.rowCount > 0) {
            filenameToDelete = fileResult.rows[0].arquivo;
        }

        const sql = `DELETE FROM tccs WHERE id = $1`;
        const resultado = await conexao.query(sql, [id]);
        
        if (resultado.rowCount === 0) {
            return res.status(404).json({ mensagem: "TCC não encontrado." });
        }

        // Se o registro foi deletado e havia um arquivo associado, tenta excluí-lo do sistema de arquivos
        if (filenameToDelete) {
            const filePath = path.join(__dirname, 'uploads', filenameToDelete);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
                console.log(`Arquivo ${filenameToDelete} excluído do sistema de arquivos.`);
            } else {
                console.warn(`Arquivo ${filenameToDelete} não encontrado no sistema de arquivos, mas o registro foi removido do DB.`);
            }
        }

        res.json({ mensagem: "TCC deletado com sucesso!" });
    } catch (error) {
        console.error("Erro ao deletar TCC:", error);
        res.status(500).json({ mensagem: "Erro ao deletar TCC." });
    }
});

// Rota para editar TCC
app.put('/editar_tcc', async (req, res) => {
    const { id, titulo, ano, autor, curso_id } = req.body;
    if (!id || !titulo || !ano || !autor || !curso_id) return res.status(400).json({ mensagem: 'Todos os campos são obrigatórios.' });
    const sql = `UPDATE tccs SET titulo = $1, ano = $2, autor = $3, curso_id = $4 WHERE id = $5`;
    try {
        const resultado = await conexao.query(sql, [titulo, ano, autor, curso_id, id]);
        if (resultado.rowCount === 0) return res.status(404).json({ mensagem: 'TCC não encontrado.' });
        res.json({ mensagem: 'TCC atualizado com sucesso!' });
    } catch (err) {
        console.error('Erro ao editar TCC:', err);
        res.status(500).json({ mensagem: 'Erro ao editar TCC.' });
    }
});

// Servir arquivos estáticos da pasta 'uploads'
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
