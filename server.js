require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

app.get('/', (req, res) => {
    res.send('Dobrodošli u sigurnosnu aplikaciju!');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server pokrenut na portu ${PORT}`);
});
