const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const Queue = require('bull');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Configuração do app e middlewares
const app = express();
app.use(bodyParser.json());
app.use(helmet());
app.use(express.static(path.join(__dirname, 'public')));

// Configuração do logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

// Configuração do Bull
const auditQueue = new Queue('auditQueue');

// Configuração de segurança e autenticação
const JWT_SECRET = process.env.JWT_SECRET;
const users = [{ id: 1, username: 'admin', password: bcrypt.hashSync('password', 8) }];

// Limite de taxa de requisições
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later',
});

app.use(limiter);

// Função de análise de contrato
const analyzeContract = (source, callback) => {
  const contractPath = `./contracts/${uuidv4()}.sol`;
  fs.writeFileSync(contractPath, source);

  exec(`myth analyze ${contractPath}`, (error, stdout, stderr) => {
    fs.unlinkSync(contractPath);
    if (error) {
      callback(stderr, null);
    } else {
      exec(`slither ${contractPath}`, (slitherError, slitherStdout, slitherStderr) => {
        if (slitherError) {
          callback(slitherStderr, null);
        } else {
          callback(null, {
            mythril: stdout,
            slither: slitherStdout,
          });
        }
      });
    }
  });
};

// Processamento da fila
auditQueue.process((job, done) => {
  analyzeContract(job.data.source, (err, result) => {
    if (err) {
      done(new Error(err));
    } else {
      done(null, result);
    }
  });
});

// Rota de login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (user && bcrypt.compareSync(password, user.password)) {
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Credenciais inválidas' });
  }
});

// Rota de análise
app.post('/analyze', (req, res) => {
  const { source } = req.body;
  const jobId = uuidv4();
  auditQueue.add({ source, jobId });
  res.json({ jobId });
});

// Rota de status
app.get('/status/:jobId', (req, res) => {
  const jobId = req.params.jobId;
  auditQueue.getJob(jobId).then(job => {
    if (job) {
      job.getState().then(state => {
        if (state === 'completed') {
          job.result.then(result => res.json({ state, result }));
        } else {
          res.json({ state });
        }
      });
    } else {
      res.status(404).json({ message: 'Job não encontrado' });
    }
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
