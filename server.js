const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');
const path = require('path');  // Required to serve static files
const cors = require('cors');   // Add CORS to handle cross-origin requests
const app = express();
const port = 3000;

// Middleware to parse JSON data in POST and PUT requests
app.use(express.json());

// Enable CORS for all origins (or restrict to a specific origin)
app.use(cors());

// Serve static files (like HTML, CSS, JS) from the public folder
app.use(express.static(path.join(__dirname, 'public')));  // Make public folder accessible

// Database client setup
const client = new Client({
  host: 'localhost',        // Database host
  port: 5432,               // Default PostgreSQL port
  user: 'myuser',           // PostgreSQL user
  password: 'ab12cd34',     // Password for user
  database: 'mydatabase'    // Database name
});

// Connect to the PostgreSQL database
client.connect()
  .then(() => console.log('Connected to PostgreSQL'))
  .catch(err => console.error('Connection error', err.stack));

// Define the root route that will serve the login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));  // Serve login.html from the public folder
});

// Register Route (POST - Create)
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user already exists
    const existingUser = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    await client.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, hashedPassword]);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login Route (POST - Authenticate)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Compare the hashed password
    const match = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!match) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Create a JWT token
    const token = jwt.sign({ id: user.rows[0].id }, 'your-secret-key', { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.error('Error logging in user:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Define the inventory route (GET - Read)
app.get('/inventory', (req, res) => {
  client.query('SELECT * FROM inventory', (err, result) => {
    if (err) {
      console.error('Error fetching inventory:', err);
      res.status(500).send('Error fetching inventory');
    } else {
      res.json(result.rows);  // Send inventory data as JSON
    }
  });
});

// POST Route: Add an inventory item (Create)
app.post('/inventory', (req, res) => {
  const { name, quantity, expiration_date } = req.body;

  // Insert the new item into the inventory
  client.query('INSERT INTO inventory (name, quantity, expiration_date) VALUES ($1, $2, $3) RETURNING *', 
    [name, quantity, expiration_date], (err, result) => {
      if (err) {
        console.error('Error adding item:', err);
        res.status(500).send('Error adding item');
      } else {
        res.status(201).json(result.rows[0]); // Return the newly created item
      }
  });
});

// PUT Route: Update an inventory item by ID (Update)
app.put('/inventory/:id', (req, res) => {
  const { id } = req.params;
  const { name, quantity, expiration_date } = req.body;

  // Update the item in the inventory
  client.query('UPDATE inventory SET name = $1, quantity = $2, expiration_date = $3 WHERE id = $4 RETURNING *', 
    [name, quantity, expiration_date, id], (err, result) => {
      if (err) {
        console.error('Error updating item:', err);
        res.status(500).send('Error updating item');
      } else if (result.rows.length === 0) {
        res.status(404).send('Item not found');
      } else {
        res.status(200).json(result.rows[0]); // Return the updated item
      }
  });
});

// DELETE Route: Delete an inventory item by ID (Delete)
app.delete('/inventory/:id', (req, res) => {
  const { id } = req.params;

  // Delete the item from the inventory
  client.query('DELETE FROM inventory WHERE id = $1 RETURNING *', [id], (err, result) => {
    if (err) {
      console.error('Error deleting item:', err);
      res.status(500).send('Error deleting item');
    } else if (result.rows.length === 0) {
      res.status(404).send('Item not found');
    } else {
      res.status(200).send('Item deleted successfully');
    }
  });
});

// Start the Express server
app.listen(port, '0.0.0.0', () => {
  console.log(`Server is running at http://0.0.0.0:${port}`);
});

// Handle server shutdown gracefully by closing the database connection
process.on('SIGINT', () => {
  console.log('Shutting down the server...');
  client.end()
    .then(() => {
      console.log('PostgreSQL connection closed.');
      process.exit(0);
    })
    .catch(err => {
      console.error('Error closing PostgreSQL connection', err.stack);
      process.exit(1);
    });
});


