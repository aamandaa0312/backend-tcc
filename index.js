require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const porta = process.env.PORT || 5432;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuração da conexão com o PostgreSQL
const conexao = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Necessário para conexões com certificados autoassinados
    }
});

// Testar a conexão com o banco de dados
conexao.connect()
    .then(() => {
        console.log("Conexão com o banco de dados estabelecida com sucesso!");
        app.listen(porta, () => {
            console.log("O servidor está rodando na porta " + porta);
        });
    })
    .catch(err => {
        console.error("Erro ao conectar ao banco de dados:", err.message);
        process.exit(1); // Encerra o processo se a conexão falhar
    });

// Rota de teste
app.get('/', (req, res) => {
    res.send('O servidor back-end do TCC está funcionando!');
});

// Exemplo de rota que usa a conexão
app.post('/exemplo', async (req, res) => {
    try {
        const resultados = await conexao.query('SELECT * FROM tabela'); // Substitua 'tabela' pelo nome da sua tabela
        res.json(resultados.rows);
    } catch (err) {
        console.error('Erro ao executar a consulta:', err);
        res.status(500).json({ erro: 'Erro ao executar a consulta' });
    }
});

// Rota para cadastrar um novo usuário
app.post('/cadastrar_usuario', async (req, res) => {
    const { nome, email, senha, tipo } = req.body;
    if (!nome || !email || !senha || !tipo) {
        return res.status(400).json({ mensagem: 'Todos os campos obrigatórios devem ser preenchidos.' });
    }
    try {
        const sql = 'INSERT INTO usuarios (nome, email, senha, tipo) VALUES ($1, $2, $3, $4)';
        await conexao.query(sql, [nome, email, senha, tipo]);
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
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha); // Certifique-se de que a senha está sendo armazenada como hash

        if (!senhaCorreta) {
            return res.status(401).json({ erro: 'Email ou senha incorretos.' });
        }
        const token = jwt.sign(
            { id: usuario.id, tipo: usuario.tipo, email: usuario.email },
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
    } catch (err) {
        console.error('Erro no login:', err);
        return res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
});

// Rota para listar usuários
app.get('/listar_usuarios', async (req, res) => {
    try {
        const sql = 'SELECT * FROM usuarios';
        const resultados = await conexao.query(sql);
        res.json(resultados.rows);
    } catch (err) {
        console.error('Erro ao listar usuários:', err);
        res.status(500).json({ erro: 'Erro ao listar usuários' });
    }
});

// Rota para editar usuário
app.put('/editar_usuario', async (req, res) => {
    const { id, nome, email, tipo } = req.body;
    if (!id || !nome || !email || !tipo) {
        return res.status(400).json({ mensagem: 'Todos os campos são obrigatórios.' });
    }
    try {
        const sql = 'UPDATE usuarios SET nome = $1, email = $2, tipo = $3 WHERE id = $4';
        const resultado = await conexao.query(sql, [nome, email, tipo, id]);
        if (resultado.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Usuário não encontrado.' });
        }
        res.json({ mensagem: 'Usuário atualizado com sucesso!' });
    } catch (err) {
        console.error('Erro ao editar usuário:', err);
        res.status(500).json({ mensagem: 'Erro ao editar usuário.' });
    }
});

// Rota para excluir usuário
app.delete('/excluir_usuario/:id', async (req, res) => {
    const { id } = req.params;
    if (!id) return res.status(400).json({ mensagem: "ID do usuário é obrigatório" });
    try {
        const resultado = await conexao.query('DELETE FROM usuarios WHERE id = $1', [id]);
        if (resultado.rowCount === 0) {
            return res.status(404).json({ mensagem: "Usuário não encontrado" });
        }
        res.json({ mensagem: "Usuário deletado com sucesso" });
    } catch (error) {
        console.error("Erro ao deletar usuário:", error);
        res.status(500).json({ mensagem: "Erro ao deletar usuário" });
    }
});

// Rota para visualizar perfil do usuário
app.get('/perfil', async (req, res) => {
    const usuarioId = req.usuario.id; // Supondo que você tenha um middleware que define req.usuario
    try {
        const sql = 'SELECT id, nome, email, tipo FROM usuarios WHERE id = $1';
        const resultados = await conexao.query(sql, [usuarioId]);
        if (resultados.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Usuário não encontrado.' });
        }
        res.status(200).json(resultados.rows[0]);
    } catch (err) {
        console.error('Erro ao buscar dados do perfil:', err);
        res.status(500).json({ mensagem: 'Erro interno do servidor.' });
    }
});

// Rota para upload de arquivos (exemplo)
app.post('/upload', (req, res) => {
    // Implementar lógica de upload
});

// Rota para listar TCCs
app.get('/listar_tccs', async (req, res) => {
    try {
        const sql = 'SELECT * FROM tccs';
        const resultados = await conexao.query(sql);
        res.json(resultados.rows);
    } catch (err) {
        console.error('Erro ao listar TCCs:', err);
        res.status(500).json({ erro: 'Erro ao listar TCCs' });
    }
});

// Rota para excluir TCC
app.delete('/excluir_tcc/:id', async (req, res) => {
    const { id } = req.params;
    if (!id) return res.status(400).json({ mensagem: "ID do TCC é obrigatório." });
    try {
        const resultado = await conexao.query('DELETE FROM tccs WHERE id = $1', [id]);
        if (resultado.rowCount === 0) {
            return res.status(404).json({ mensagem: "TCC não encontrado." });
        }
        res.json({ mensagem: "TCC deletado com sucesso!" });
    } catch (error) {
        console.error("Erro ao deletar TCC:", error);
        res.status(500).json({ mensagem: "Erro ao deletar TCC." });
    }
});

// Rota para editar TCC
app.put('/editar_tcc', async (req, res) => {
    const { id, titulo, ano, autor } = req.body;
    if (!id || !titulo || !ano || !autor) {
        return res.status(400).json({ mensagem: 'Todos os campos são obrigatórios.' });
    }
    try {
        const sql = 'UPDATE tccs SET titulo = $1, ano = $2, autor = $3 WHERE id = $4';
        const resultado = await conexao.query(sql, [titulo, ano, autor, id]);
        if (resultado.rowCount === 0) {
            return res.status(404).json({ mensagem: 'TCC não encontrado.' });
        }
        res.json({ mensagem: 'TCC atualizado com sucesso!' });
    } catch (err) {
        console.error('Erro ao editar TCC:', err);
        res.status(500).json({ mensagem: 'Erro ao editar TCC.' });
    }
});

// Servir arquivos estáticos da pasta 'uploads'
app.use('/uploads', express.static('uploads'));
