
import express from 'express';
import session from 'express-session';
import bcrypt from 'bcrypt';

import { PrismaClient } from '@prisma/client';
import { PrismaNeonHTTP } from '@prisma/adapter-neon';

// 1. Check that the database connection string exists
if (!process.env.DATABASE_URL) {
  throw new Error(
    'DATABASE_URL not loaded — start with: node --watch --env-file=.env index.js'
  );
}

// 2. Initialize Prisma with the Neon HTTPS adapter
const adapter = new PrismaNeonHTTP(process.env.DATABASE_URL, {});

const prisma = new PrismaClient({ adapter });

// 3. Initialize Express
const app = express();

// 4. Middleware
app.use(express.json());

app.use(session({
  secret: 'docchat-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: 1000 * 60 * 60 * 24
  }
}));

// 5. Route: GET /api/health
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Server is alive'
  });
});

// 6. Route: POST /api/register
app.post('/api/register', async (req, res) => {
  const { email, name, password } = req.body;
    console.log('Registration request received:', {
    email,
    name,
    passwordReceived: Boolean(password)
  });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email,
        name,
        password: hashedPassword
      }
    });

    req.session.userId = user.id;

    res.status(201).json({
      id: user.id,
      name: user.name
    });

  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(400).json({
        error: 'Email already registered'
      });
    }

    res.status(500).json({
      error: 'Registration failed'
    });
  }
});

// 7. Route: POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }
    req.session.userId = user.id;

    res.json({
      id: user.id,
      name: user.name
    });

  } catch (error) {
    res.status(500).json({
      error: 'Login failed'
    });
  }
});

// 8. Route: GET /api/me
app.get('/api/me', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      error: 'Not authenticated'
    });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
      select: {
        id: true,
        name: true,
        email: true
      }
    });

    if (!user) {
      return res.status(401).json({
        error: 'User not found'
      });
    }

    res.json(user);

  } catch (error) {
    res.status(500).json({
      error: 'Failed to get user'
    });
  }
});

// 9. Route: POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        error: 'Logout failed'
      });
    }

    res.clearCookie('connect.sid');

    res.json({
      message: 'Logged out successfully'
    });
  });
});

// 10. Start the server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
