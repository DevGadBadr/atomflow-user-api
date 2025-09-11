import request from 'supertest';
import express from 'express';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import path from 'path';
import dotenv from 'dotenv';
import pg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Load environment variables
dotenv.config();

// Import the server app
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();

// Test database connection
const pool = new pg.Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

describe('Server API Tests', () => {
    let testToken;
    let testUserId;

    beforeAll(async () => {
        // Create a test user
        const username = 'testuser';
        const password = 'testpass123';
        const email = 'test@example.com';
        const mobile = '1234567890';
        const name = 'Test User';
        const role = 'user';
        const location = 'Test Location';
        const roles = JSON.stringify({ '1': { name: 'User' } });

        const passwordHash = await bcrypt.hash(password, 10);
        
        const result = await pool.query(
            `INSERT INTO users (username, password_hash, email, role, created_at, mobilenumber, name, location, roles)
             VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour', $5, $6, $7, $8)
             RETURNING id`,
            [username, passwordHash, email, role, mobile, name, location, roles]
        );

        testUserId = result.rows[0].id;
        testToken = jwt.sign(
            { id: testUserId, email: username },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );
    });

    afterAll(async () => {
        // Clean up test user
        await pool.query('DELETE FROM users WHERE id = $1', [testUserId]);
        await pool.end();
    });

    test('GET / should return "API IS GOOD"', async () => {
        const response = await request(app).get('/');
        expect(response.status).toBe(200);
        expect(response.text).toBe('API IS GOOD');
    });

    test('GET /sayhello should return "API IS Saying Hello"', async () => {
        const response = await request(app).get('/sayhello');
        expect(response.status).toBe(200);
        expect(response.text).toBe('API IS Saying Hello');
    });

    test('POST /validateuser should authenticate valid user', async () => {
        const response = await request(app)
            .post('/validateuser')
            .send({
                username: 'testuser',
                password: 'testpass123',
                rememberme: true
            });

        expect(response.status).toBe(200);
        expect(response.body.res).toBe('authorized');
        expect(response.body.token).toBeDefined();
    });

    test('GET /user/roles/:userId should return user roles', async () => {
        const response = await request(app)
            .get(`/user/roles/${testUserId}`)
            .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        expect(response.body.roles).toBeDefined();
    });

    test('PUT /user/roles/:userId should update user roles', async () => {
        const newRoles = { '1': { name: 'User' }, '2': { name: 'Admin' } };
        const response = await request(app)
            .put(`/user/roles/${testUserId}`)
            .set('Authorization', `Bearer ${testToken}`)
            .send({ roles: newRoles });

        expect(response.status).toBe(200);
        expect(response.body.roles).toEqual(newRoles);
    });

    test('POST /user/check-role should check if user has role', async () => {
        const response = await request(app)
            .post('/user/check-role')
            .set('Authorization', `Bearer ${testToken}`)
            .send({
                userId: testUserId,
                roleId: '1'
            });

        expect(response.status).toBe(200);
        expect(response.body.hasRole).toBeDefined();
    });
}); 