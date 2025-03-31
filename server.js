const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');
const cors = require('cors');

const app = express();
const port = 3000;

// Middleware
app.use(cors()); // Enable CORS so frontend on port 80 can call backend
app.use(express.json()); // Parse JSON bodies

// PostgreSQL client setup
const client = new Client({
  host: 'localhost',
  port: 5432,
  user: 'myuser',
  password: 'ab12cd34',
  database: 'mydatabase'
});

client.connect()
  .then(() => console.log('✅ Connected to PostgreSQL'))
  .catch(err => console.error('❌ PostgreSQL connection error:', err.stack));

// =========================
// === API ROUTES BELOW ===
// =========================

// Register new user
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await client.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2)',
      [email, hashedPassword]
    );

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Error in /register:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login existing user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const match = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!match) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.rows[0].id }, 'your-secret-key', { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Error in /login:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get full inventory
app.get('/inventory', (req, res) => {
  client.query('SELECT * FROM inventory', (err, result) => {
    if (err) {
      console.error('Error fetching inventory:', err);
      res.status(500).send('Error fetching inventory');
    } else {
      res.json(result.rows);
    }
  });
});

// Add new inventory item
app.post('/inventory', (req, res) => {
  const { name, quantity, expiration_date } = req.body;

  client.query(
    'INSERT INTO inventory (name, quantity, expiration_date) VALUES ($1, $2, $3) RETURNING *',
    [name, quantity, expiration_date],
    (err, result) => {
      if (err) {
        console.error('Error adding item:', err);
        res.status(500).send('Error adding item');
      } else {
        res.status(201).json(result.rows[0]);
      }
    }
  );
});

// Update inventory item by ID
app.put('/inventory/:id', (req, res) => {
  const { id } = req.params;
  const { name, quantity, expiration_date } = req.body;

  client.query(
    'UPDATE inventory SET name = $1, quantity = $2, expiration_date = $3 WHERE id = $4 RETURNING *',
    [name, quantity, expiration_date, id],
    (err, result) => {
      if (err) {
        console.error('Error updating item:', err);
        res.status(500).send('Error updating item');
      } else if (result.rows.length === 0) {
        res.status(404).send('Item not found');
      } else {
        res.json(result.rows[0]);
      }
    }
  );
});

// Delete inventory item by ID
app.delete('/inventory/:id', (req, res) => {
  const { id } = req.params;

  client.query(
    'DELETE FROM inventory WHERE id = $1 RETURNING *',
    [id],
    (err, result) => {
      if (err) {
        console.error('Error deleting item:', err);
        res.status(500).send('Error deleting item');
      } else if (result.rows.length === 0) {
        res.status(404).send('Item not found');
      } else {
        res.send('Item deleted successfully');
      }
    }
  );
});

// Autocomplete search
app.get('/inventory/suggestions', (req, res) => {
  const searchQuery = req.query.q;

  client.query(
    'SELECT * FROM inventory WHERE name ILIKE $1 LIMIT 10',
    [`${searchQuery}%`],
    (err, result) => {
      if (err) {
        console.error('Error fetching suggestions:', err);
        res.status(500).send('Error fetching suggestions');
      } else {
        res.json(result.rows);
      }
    }
  );
});

// Start server on port 3000
app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 API server running at http://0.0.0.0:${port}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down server...');
  client.end()
    .then(() => {
      console.log('PostgreSQL connection closed.');
      process.exit(0);
    })
    .catch(err => {
      console.error('Error closing PostgreSQL connection:', err.stack);
      process.exit(1);
    });
});

