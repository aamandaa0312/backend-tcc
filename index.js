

require('dotenv').config();
const express = require('express')
const mysql = require('mysql2')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt');
const bcryptjs = require('bcryptjs');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const porta = 3000
const app = express()
app.use(express.json())
const cors = require('cors');

const PORTA = 3000;
const JWT_SECRET = 'sua_chave_secreta_para_assinatura_de_tokens'; // CHAVE SECRETA FIXA AQUI
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
        fileSize: 1024 * 1024 * 30 // Limite de 10MB
    }
});

const conexao = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    port: 3306,
    database: "tcc"
})




app.listen(porta, () => {
    console.log("o servidor está rodando")
})

// inicio rotas usuario


// Middleware para verificar o token JWT
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

const saltRounds = 10;

// Rota para cadastrar um novo usuário
app.post('/cadastrar_usuario', async (req, res) => {
    const { nome, email, senha, tipo, curso_id, matricula } = req.body; // Adicione 'matricula' aqui

    if (!nome || !email || !senha || !tipo) {
        return res.status(400).json({ mensagem: 'Todos os campos obrigatórios devem ser preenchidos.' });
    }
    

    try {
        const senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);

        const checkSql = 'SELECT * FROM usuarios WHERE email = ?';
        conexao.query(checkSql, [email], (checkErr, checkResult) => {
            if (checkErr) {
                console.error('Erro ao verificar usuário:', checkErr);
                return res.status(500).json({ mensagem: 'Erro interno do servidor.' });
            }
            if (checkResult.length > 0) {
                return res.status(409).json({ mensagem: 'Usuário com este email já existe.' });
            }

            const sql = 'INSERT INTO usuarios (nome, email, senha, tipo, curso_id) VALUES (?, ?, ?, ?, ?)';
            conexao.query(sql, [nome, email, senhaHash, tipo, curso_id], (err, result) => {
                if (err) {
                    console.error('Erro ao cadastrar usuário:', err);
                    return res.status(500).json({ mensagem: 'Erro ao cadastrar usuário.' });
                }
                res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso!' });
            });
        });
    } catch (err) {
        console.error('Erro ao gerar hash da senha:', err);
        res.status(500).json({ mensagem: 'Erro interno do servidor.' });
    }
});


app.post('/login', async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ erro: 'Email e senha são obrigatórios.' });
    }

    const sql = 'SELECT * FROM usuarios WHERE email = ?';
    conexao.query(sql, [email], async (err, resultados) => {
        if (err) {
            console.error('Erro ao buscar usuário:', err);
            return res.status(500).json({ erro: 'Erro interno do servidor.' });
        }

        if (resultados.length === 0) {
            return res.status(401).json({ erro: 'Email ou senha incorretos.' });
        }

        const usuario = resultados[0];

        try {
            // Comparar a senha fornecida com o hash armazenado na coluna 'senha'
            const senhaCorreta = await bcrypt.compare(senha, usuario.senha);

            if (!senhaCorreta) {
                return res.status(401).json({ erro: 'Email ou senha incorretos.' });
            }

            // Geração do Token JWT
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

        } catch (erroBcrypt) {
            console.error('Erro ao comparar senha:', erroBcrypt);
            return res.status(500).json({ erro: 'Erro interno do servidor durante a autenticação.' });
        }
    });
});



app.delete('/excluir_usuario/:id', (req, res) => {
    const { id } = req.params;

    if (!id) {
        return res.status(400).json({ mensagem: "ID do usuário é obrigatório" });
    }

    const sql = `DELETE FROM usuarios WHERE id = ?`;

    conexao.query(sql, [id], (error, resultado) => {
        if (error) {
            console.error("Erro ao deletar usuário:", error);
            return res.status(500).json({ mensagem: "Erro ao deletar usuário" });
        }
        if (resultado.affectedRows === 0) {
            return res.status(404).json({ mensagem: "Usuário não encontrado" });
        }
        res.json({ mensagem: "Usuário deletado com sucesso" });
    });
});

app.get('/listar_usuarios', (req, res) => {
    const sql = `
        SELECT 
            usuarios.id, 
            usuarios.nome, 
            usuarios.email, 
            CASE 
                WHEN usuarios.tipo = 'administrador' THEN 'admin'
                ELSE usuarios.tipo
            END as tipo,
            IF(usuarios.tipo = 'aluno', cursos.curso, NULL) AS curso
        FROM usuarios
        LEFT JOIN cursos ON usuarios.curso_id = cursos.id
    `;

    conexao.query(sql, (err, resultados) => {
        if (err) {
            console.error("Erro ao listar usuários:", err);
            return res.status(500).json({ erro: 'Erro ao listar usuários' });
        }
        res.json(resultados);
    });
});

app.put('/editar_usuario', (req, res) => {
    const { id, nome, email, tipo, curso_id } = req.body;

    console.log("Dados recebidos para edição:", req.body);
    if (!id || !nome?.trim() || !email?.trim() || !tipo?.trim()) {
        return res.status(400).json({ mensagem: "Preencha todos os campos obrigatórios" });
    }

    const tipoNormalizado = tipo === 'admin' ? 'administrador' : tipo;
    const cursoIdTratado = curso_id === '' ? null : curso_id;

    if (tipoNormalizado === 'aluno') {
        const sql = `UPDATE usuarios SET nome = ?, email = ?, tipo = ?, curso_id = ? WHERE id = ?`;
        conexao.execute(sql, [nome, email, tipoNormalizado, cursoIdTratado, id], (error, resultado) => {
            if (error) {
                console.error("Erro ao editar usuário:", error);
                return res.status(500).json({ mensagem: "Erro ao editar usuário" });
            }
            if (resultado.affectedRows === 0) {
                return res.status(404).json({ mensagem: "Usuário não encontrado" });
            }
            res.json({ mensagem: "Usuário atualizado com sucesso" });
        });
    } else {
        const sql = `UPDATE usuarios SET nome = ?, email = ?, tipo = ?, curso_id = NULL WHERE id = ?`;
        conexao.execute(sql, [nome, email, tipoNormalizado, id], (error, resultado) => {
            if (error) {
                console.error("Erro ao editar usuário:", error);
                return res.status(500).json({ mensagem: "Erro ao editar usuário" });
            }
            if (resultado.affectedRows === 0) {
                return res.status(404).json({ mensagem: "Usuário não encontrado" });
            }
            res.json({ mensagem: "Usuário atualizado com sucesso" });
        });
    }
});


app.get('/perfil', verificarToken, (req, res) => {

    const usuarioId = req.usuario.id;

    const sql = 'SELECT id, nome, email, tipo FROM usuarios WHERE id = ?';
    conexao.query(sql, [usuarioId], (err, resultados) => {
        if (err) {
            console.error('Erro ao buscar dados do perfil:', err);
            return res.status(500).json({ mensagem: 'Erro interno do servidor.' });
        }
        if (resultados.length === 0) {
            return res.status(404).json({ mensagem: 'Usuário não encontrado.' });
        }

        res.status(200).json(resultados[0]);
    });
});


// Fim rotas usuario    



app.get('/listar_tccs', (req, res) => {
    const { status } = req.query;

    let sql = 'SELECT tccs.*, cursos.curso FROM tccs JOIN cursos ON tccs.curso_id = cursos.id';
    const params = [];

    if (status) {
        sql += ' WHERE tccs.status = ?';
        params.push(status);
    }

    conexao.query(sql, params, (err, resultados) => {
        if (err) return res.status(500).json({ erro: 'Erro ao listar TCCs' });
        res.json(resultados);
    });
});

// rota para listar tccs por ano
app.get("/listar_tccs_por_ano", async (req, res) => {
    const { ano } = req.query;

    if (!ano) {
        return res.status(400).json({ erro: "O ano é obrigatório!" });
    }

    try {
        const [tccs] = await conexao.promise().query("SELECT * FROM tccs WHERE ano = ?", [ano]);

        if (tccs.length === 0) {
            return res.json({ mensagem: "Nenhum TCC encontrado para este ano." });
        }

        res.json(tccs);
    } catch (erro) {
        console.error("Erro ao buscar os TCCs:", erro);
        res.status(500).json({ erro: "Erro ao buscar os TCCs." });
    }
});


// tcc e ano

app.get('/tccs', (req, res) => {
    const { curso_id, ano, status } = req.query;

    let sql = `
        SELECT tccs.*, cursos.curso 
        FROM tccs 
        INNER JOIN cursos ON tccs.curso_id = cursos.id
        WHERE tccs.status = ?
    `;

    const params = ['aprovado']; // Filtro fixo para aprovados

    // Filtros opcionais
    if (curso_id) {
        sql += ' AND cursos.id = ?';
        params.push(curso_id);
    }
    if (ano) {
        sql += ' AND tccs.ano = ?';
        params.push(ano);
    }

    sql += ' ORDER BY tccs.ano DESC, tccs.titulo ASC';

    conexao.query(sql, params, (error, resultados) => {
        if (error) {
            console.error('Erro ao buscar TCCs:', error);
            return res.status(500).json({ erro: 'Falha ao filtrar TCCs' });
        }
        res.json(resultados);
    });
});




// INICIO ROTAS DE CURSO
// Rota para cadastrar curso

app.post('/cadastrar_curso', (req, res) => {
    const { curso } = req.body;

    if (!curso || !curso.trim()) {
        return res.status(400).json({ erro: 'O nome do curso é obrigatório' });
    }

    const sql = 'INSERT INTO cursos (curso) VALUES (?)';
    conexao.query(sql, [curso], (err, result) => {
        if (err) {
            console.error('Erro ao cadastrar curso:', err);
            return res.status(500).json({ erro: 'Erro ao cadastrar curso' });
        }
        res.json({ mensagem: "Curso cadastrado com sucesso!" });
    });
});


// Rota para listar cursos

app.get('/listar_cursos', (req, res) => {
    const sql = 'SELECT id, curso FROM cursos';
    conexao.query(sql, (err, resultados) => {
        if (err) {
            return res.status(500).json({ erro: 'Erro ao listar cursos' });
        }
        res.json(resultados);
    });
});
app.delete('/excluir_curso/:id', (req, res) => {
    const { id } = req.params;

    if (!id) {
        return res.status(400).json({ mensagem: "ID do curso é obrigatório" });
    }

    const sql = `DELETE FROM cursos WHERE id = ?`;

    conexao.query(sql, [id], (error, resultado) => {
        if (error) {
            if (error.code === 'ER_ROW_IS_REFERENCED_2') {
                return res.status(400).json({ mensagem: "Este curso está vinculado a TCCs e não pode ser excluído." });
            }
            nsole.error("Erro ao deletar curso:", error);
            return res.status(500).json({ mensagem: "Erro ao deletar curso" });
        }

        if (resultado.affectedRows === 0) {
            return res.status(404).json({ mensagem: "Curso não encontrado" });
        }

        res.json({ mensagem: "Curso deletado com sucesso" });
    });
});





app.put('/editar_curso', (req, res) => {
    const { id, curso } = req.body;

    if (!id || !curso || !curso.trim()) {
        return res.status(400).json({ mensagem: 'ID e nome do curso são obrigatórios' });
    }

    const sql = `UPDATE cursos SET curso = ? WHERE id = ?`;

    conexao.query(sql, [curso, id], (err, result) => {
        if (err) {
            console.error('Erro ao editar curso:', err);
            return res.status(500).json({ mensagem: 'Erro ao editar curso' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ mensagem: 'Curso não encontrado' });
        }

        res.json({ mensagem: 'Curso atualizado com sucesso!' });
    });
});




// INTRANET


app.post('/login', (req, res) => {
    const { matricula, senha } = req.body;

    if (!matricula || !senha) {
        return res.status(400).json({ erro: 'Matrícula e senha são obrigatórios.' });
    }

    const sql = 'SELECT * FROM usuarios WHERE matricula = ?';
    conexao.query(sql, [matricula], async (err, resultados) => {
        if (err) {
            console.error('Erro ao buscar usuário:', err);
            return res.status(500).json({ erro: 'Erro interno do servidor.' });
        }

        if (resultados.length === 0) {
            return res.status(401).json({ erro: 'Matrícula ou senha incorretos.' });
        }

        const usuario = resultados[0];

        const senhaCorreta = await bcrypt.compare(senha, usuario.senha_hash);

        if (!senhaCorreta) {
            return res.status(401).json({ erro: 'Matrícula ou senha incorretos.' });
        }


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
    });
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
app.post('/upload_tcc', upload.single('arquivo'), (req, res) => {
    console.log('Corpo da requisição:', req.body);
    console.log('Arquivo recebido:', req.file);

    const { titulo, ano, autor, curso } = req.body;
    const arquivo = req.file;

    const sqlCurso = 'SELECT id FROM cursos WHERE id = ?';

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

    conexao.query(sqlCurso, [curso], (err, resultCurso) => {
        if (err) {
            console.error('Erro ao verificar curso:', err);
            fs.unlinkSync(arquivo.path);
            return res.status(500).json({ erro: 'Erro ao verificar curso' });
        }

        if (resultCurso.length === 0) {
            fs.unlinkSync(arquivo.path);
            return res.status(400).json({ erro: 'Curso não encontrado' });
        }

        const cursoId = resultCurso[0].id;
        const sql = 'INSERT INTO tccs (titulo, ano, autor, curso_id, arquivo, status) VALUES (?, ?, ?, ?, ?, ?)';

        conexao.query(sql, [titulo, ano, autor, cursoId, arquivo.filename, 'pendente'], (err, result) => {
            if (err) {
                console.error('Erro ao inserir no banco:', err);
                fs.unlinkSync(arquivo.path);
                return res.status(500).json({ erro: 'Erro ao salvar TCC no banco de dados', detalhes: err.message });
            }
            res.json({ mensagem: 'TCC cadastrado com sucesso!' });
        });
    });
});

// Rota para aprovar/rejeitar TCC
app.post('/avaliar_tcc', (req, res) => {
    const { id, status, comentario } = req.body;

    if (!id || isNaN(id)) {
        return res.status(400).json({ erro: 'ID do TCC inválido' });
    }

    if (!['aprovado', 'rejeitado'].includes(status)) {
        return res.status(400).json({ erro: 'Status inválido. Deve ser "aprovado" ou "rejeitado"' });
    }

    const checkSql = 'SELECT * FROM tccs WHERE id = ?';
    conexao.query(checkSql, [id], (err, results) => {
        if (err) {
            console.error('Erro ao verificar TCC:', err);
            return res.status(500).json({ erro: 'Erro ao verificar TCC' });
        }

        if (results.length === 0) {
            return res.status(404).json({ erro: 'TCC não encontrado' });
        }

        const updateSql = 'UPDATE tccs SET status = ?, comentario = ?, avaliado_em = NOW() WHERE id = ?';
        conexao.query(updateSql, [status, comentario || null, id], (err2) => {
            if (err2) {
                console.error('Erro ao atualizar TCC:', err2);
                return res.status(500).json({ erro: 'Erro ao atualizar TCC' });
            }

            res.json({
                mensagem: `TCC ${status} com sucesso!`,
                dados: {
                    id,
                    status,
                    comentario
                }
            });
        });
    });
});



app.delete('/excluir_tcc/:id', (req, res) => {
    const { id } = req.params;

    if (!id) {
        return res.status(400).json({ mensagem: "ID do TCC é obrigatório" });
    }

    const sql = `DELETE FROM tccs WHERE id = ?`;

    conexao.query(sql, [id], (error, resultado) => {
        if (error) {
            console.error("Erro ao deletar TCC:", error);
            return res.status(500).json({ mensagem: "Erro ao deletar TCC" });
        }
        if (resultado.affectedRows === 0) {
            return res.status(404).json({ mensagem: "TCC não encontrado" });
        }
        res.json({ mensagem: "TCC deletado com sucesso" });
    });
});

app.put('/editar_tcc', (req, res) => {
    const { id, titulo, ano, autor, curso_id } = req.body;

    if (!id || !titulo || !ano || !autor || !curso_id) {
        return res.status(400).json({ mensagem: 'Todos os campos são obrigatórios' });
    }

    const sql = `UPDATE tccs SET titulo = ?, ano = ?, autor = ?, curso_id = ? WHERE id = ?`;

    conexao.query(sql, [titulo, ano, autor, curso_id, id], (err, result) => {
        if (err) {
            console.error('Erro ao editar TCC:', err);
            return res.status(500).json({ mensagem: 'Erro ao editar TCC' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ mensagem: 'TCC não encontrado' });
        }

        res.json({ mensagem: 'TCC atualizado com sucesso!' });
    });
});


app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

