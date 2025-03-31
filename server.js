const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');
const cors = require('cors');

const app = express();
const port = 3000;

// Middleware
app.use(cors({
  origin: 'http://10.111.20.126:80', // Allow requests from the frontend on port 80
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allow these methods
  allowedHeaders: ['Content-Type', 'Authorization'], // Allow these headers
}));

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

// ===========================
// === Middleware for JWT Authentication ===
// ===========================

// Middleware to verify JWT and extract user information
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization') && req.header('Authorization').split(' ')[1];

  if (!token) {
    return res.status(403).json({ message: 'Token required' });
  }

  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user; // Attach user info to request
    next();
  });
};

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

// Get inventory for logged-in user
app.get('/inventory', authenticateJWT, (req, res) => {
  client.query('SELECT * FROM inventory WHERE user_id = $1', [req.user.id], (err, result) => {
    if (err) {
      console.error('Error fetching inventory:', err);
      res.status(500).send('Error fetching inventory');
    } else {
      res.json(result.rows); // Send inventory data specific to the user
    }
  });
});

// Add new inventory item for logged-in user
app.post('/inventory', authenticateJWT, (req, res) => {
  const { name, quantity, expiration_date, type } = req.body;

  // Ensure the user ID is captured from the JWT
  client.query(
    'INSERT INTO inventory (name, quantity, expiration_date, type, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
    [name, quantity, expiration_date, type, req.user.id],
    (err, result) => {
      if (err) {
        console.error('Error adding item:', err);
        res.status(500).send('Error adding item');
      } else {
        res.status(201).json(result.rows[0]); // Successfully added the item
      }
    }
  );
});

// PUT route: Update the quantity of an item after it is used
app.put('/inventory/:id/use', authenticateJWT, (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body; // Quantity to be used

  // Check if the item exists
  client.query('SELECT * FROM inventory WHERE id = $1 AND user_id = $2', [id, req.user.id], (err, result) => {
    if (err) {
      console.error('Error fetching item:', err);
      return res.status(500).send('Error fetching item');
    }

    if (result.rows.length === 0) {
      return res.status(404).send('Item not found or unauthorized');
    }

    const currentQuantity = result.rows[0].quantity;

    // Check if there’s enough quantity to reduce
    if (currentQuantity < quantity) {
      return res.status(400).send('Not enough quantity to use');
    }

    // Update the quantity (if it's greater than the used amount)
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
          res.json(result.rows[0]); // Return updated item
        }
      );
    } else {
      // If the quantity reaches zero, remove the item
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

// DELETE route: Remove an item from inventory completely
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

// Autocomplete search for inventory items (user-specific)
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
