const express = require('express');
const supabase = require('./supabaseClient'); // your Supabase client
require('dotenv').config();

const app = express();
app.use(express.json());

// Test route
app.get('/', (req, res) => res.send('Server is running!'));

// Email validation helper
const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    try {
        // Get token from Authorization header
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer <token>"
        
        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        // Verify token with Supabase
        const { data: { user }, error } = await supabase.auth.getUser(token);
        
        if (error || !user) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }

        // Attach user to request object for use in routes
        req.user = user;
        next(); // Continue to the next middleware/route
    } catch (error) {
        return res.status(401).json({ error: 'Authentication failed' });
    }
};

// Public routes
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format' });

    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) return res.status(400).json({ error: error.message });

    res.json({ message: 'Registration successful!', data });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format' });

    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return res.status(400).json({ error: error.message });

    res.json({ message: 'Login successful!', session: data.session });
});

// Protected routes (require authentication)
app.get('/profile', authenticateToken, async (req, res) => {
    res.json({ 
        message: 'Profile accessed successfully',
        user: req.user 
    });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
