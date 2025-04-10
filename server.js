const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');
const cors = require('cors');
const fetch = require('node-fetch'); // ← Added for Spoonacular UPC lookup

const app = express();
const port = 3000;

// === CORS Configuration ===
app.use(cors());
app.use(express.json());

// === PostgreSQL Setup ===
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

// === JWT Authentication Middleware ===
const authenticateJWT = (req, res, next) => {
  const authHeader = req.header('Authorization');
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(403).json({ message: 'Token required' });
  }

  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// === Routes ===

// Register
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    const existing = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
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

// Login
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

// Get inventory
app.get('/inventory', authenticateJWT, (req, res) => {
  client.query('SELECT * FROM inventory WHERE user_id = $1', [req.user.id], (err, result) => {
    if (err) {
      console.error('Error fetching inventory:', err);
      res.status(500).send('Error fetching inventory');
    } else {
      res.json(result.rows);
    }
  });
});

// Add inventory item
app.post('/inventory', authenticateJWT, (req, res) => {
  const { name, quantity, unit, expiration_date, type, upc } = req.body;

  if (quantity > 1000) {
    return res.status(400).json({ error: 'Quantity cannot exceed 1000' });
  }

  client.query(
    'INSERT INTO inventory (name, quantity, unit, expiration_date, type, upc, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
    [name, quantity, unit, expiration_date, type, upc, req.user.id],
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

// Use item
app.put('/inventory/:id/use', authenticateJWT, (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;

  client.query('SELECT * FROM inventory WHERE id = $1 AND user_id = $2', [id, req.user.id], (err, result) => {
    if (err) {
      console.error('Error fetching item:', err);
      return res.status(500).send('Error fetching item');
    }

    if (result.rows.length === 0) {
      return res.status(404).send('Item not found or unauthorized');
    }

    const currentQuantity = result.rows[0].quantity;
    const newQuantity = currentQuantity - quantity;

    if (newQuantity > 0) {
      client.query(
        'UPDATE inventory SET quantity = $1 WHERE id = $2 AND user_id = $3 RETURNING *',
        [newQuantity, id, req.user.id],
        (err, result) => {
          if (err) {
            console.error('Error updating item:', err);
            return res.status(500).send('Error updating item');
          }
          res.json(result.rows[0]);
        }
      );
    } else {
      client.query(
        'DELETE FROM inventory WHERE id = $1 AND user_id = $2 RETURNING *',
        [id, req.user.id],
        (err, result) => {
          if (err) {
            console.error('Error deleting item:', err);
            return res.status(500).send('Error deleting item');
          }
          res.send('Item deleted successfully');
        }
      );
    }
  });
});

// ✏️ Edit inventory item
app.put('/inventory/:id', authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const { name, quantity, unit, expiration_date } = req.body;

  try {
    const result = await client.query(
      'UPDATE inventory SET name = $1, quantity = $2, unit = $3, expiration_date = $4 WHERE id = $5 AND user_id = $6 RETURNING *',
      [name, quantity, unit, expiration_date, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Item not found or unauthorized' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating item:', err);
    res.status(500).json({ message: 'Failed to update item' });
  }
});

// Delete item
app.delete('/inventory/:id', authenticateJWT, (req, res) => {
  const { id } = req.params;

  client.query(
    'DELETE FROM inventory WHERE id = $1 AND user_id = $2 RETURNING *',
    [id, req.user.id],
    (err, result) => {
      if (err) {
        console.error('Error deleting item:', err);
        res.status(500).send('Error deleting item');
      } else if (result.rows.length === 0) {
        res.status(404).send('Item not found or unauthorized');
      } else {
        res.send('Item deleted successfully');
      }
    }
  );
});

// Suggestions for search bar
app.get('/inventory/suggestions', authenticateJWT, (req, res) => {
  const searchQuery = req.query.q;

  client.query(
    'SELECT * FROM inventory WHERE name ILIKE $1 AND user_id = $2 LIMIT 10',
    [`${searchQuery}%`, req.user.id],
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

// 📦 UPC Lookup (NEW!)
app.get('/upc-lookup/:code', async (req, res) => {
  const upc = req.params.code;
  const apiKey = '51793868eaea480eab4b25e7482cd178';
  const url = `https://api.spoonacular.com/food/products/upc/${upc}?apiKey=${apiKey}`;

  try {
    const response = await fetch(url);
    const data = await response.json();
    if (response.ok && data.title) {
      res.json({ title: data.title });
    } else {
      res.status(404).json({ message: 'No product found' });
    }
  } catch (err) {
    console.error('UPC lookup error:', err);
    res.status(500).json({ message: 'Error fetching from Spoonacular' });
  }
});

// Start server
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
