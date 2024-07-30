const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const argon2 = require('argon2');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    store: new SQLiteStore({ db: 'sessions.sqlite3' }),
    secret: 'your_secret_key_here',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 1 week
}));

// Database setup
const db = new sqlite3.Database('./database.sqlite3');

// Initialize database schema (create users table if not exists)
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    `);
});

// Serve static files (e.g., CSS, client-side JavaScript)
app.use(express.static(path.join(__dirname, 'public')));
app.use('/lib', express.static(path.join(__dirname, 'lib')));

// Route to serve index.html on root request
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Registration endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Hash password using argon2
        const hashedPassword = await argon2.hash(password);

        // Insert user into database
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Registration failed');
            }
            res.send('Registration successful');
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Registration failed');
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Retrieve user from database
        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Login failed');
            }
            if (!row) {
                return res.status(404).send('User not found');
            }

            // Verify password using argon2
            const isPasswordValid = await argon2.verify(row.password, password);
            if (!isPasswordValid) {
                return res.status(401).send('Invalid password');
            }

            // Store username in session
            req.session.user = username;

            // Redirect to home page upon successful login
            res.redirect('/home');
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Login failed');
    }
});

// Route to serve home.html after successful login
app.get('/home', (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.status(401).send('Unauthorized');
    }
    // Serve home.html
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Logout endpoint
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Logout failed');
        }
        res.send('Logout successful');
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
