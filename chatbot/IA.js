require('dotenv').config();
const { GoogleGenerativeAI } = require('@google/generative-ai');

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

async function chamarGemini(modelName, mensagem) {
  const model = genAI.getGenerativeModel({ model: modelName });
  const chatSession = model.startChat({
    history: [],
    generationConfig: {
      maxOutputTokens: 500,
    }
  });

  const result = await chatSession.sendMessage(mensagem);
  return result.response.text();
}

async function executar(mensagem) {
  const modelos = ["gemini-1.5-flash-latest", "gemini-1.5-pro-latest"];
  const maxTentativas = 3;

  for (const modelo of modelos) {
    for (let tentativa = 1; tentativa <= maxTentativas; tentativa++) {
      try {
        console.log(`🔄 Tentando modelo ${modelo} | Tentativa ${tentativa}`);
        const resposta = await chamarGemini(modelo, mensagem);
        return resposta;
      } catch (error) {
        if (error.status === 503) {
          console.warn(`⚠️ Modelo ${modelo} sobrecarregado. Tentando novamente (${tentativa}/${maxTentativas})...`);
          await new Promise(res => setTimeout(res, 1000 * tentativa)); // espera crescente
        } else {
          console.error("❌ Erro inesperado:", error);
          throw error;
        }
      }
    }
    console.log(`❌ Modelo ${modelo} falhou. Tentando próximo modelo...`);
  }

  // Se todos falharem
  return "⚠️ O sistema está temporariamente indisponível. Tente novamente em alguns segundos.";
}

module.exports = { executar };
