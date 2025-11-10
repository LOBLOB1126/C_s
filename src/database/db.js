import pg from 'pg';
import 'dotenv/config';

const pool = new pg.Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
});

export const query = (text, params) => pool.query(text, params);
export const getClient = () => pool.connect();