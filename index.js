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
const porta = process.env.PORT || 3000;
const app = express();
app.use(express.json());
const SALT_ROUNDS = 10; // Custo do hash para bcrypt
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE']
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
