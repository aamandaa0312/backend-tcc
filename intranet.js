
document.getElementById('loginForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const matricula = document.getElementById('matricula').value;
    const senha = document.getElementById('senha').value;

    try {
        const response = await fetch('http://localhost:3000/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ matricula, senha })
        });

        const data = await response.json();

        if (response.ok) {
            // Salvar em localStorage se quiser manter sessão
            localStorage.setItem('adminId', data.adminId);

            // Redireciona para painel
            window.location.href = 'cadastro.html';
        } else {
            alert(data.mensagem);
        }
    } catch (error) {
        alert('Erro ao conectar com o servidor');
    }
});

