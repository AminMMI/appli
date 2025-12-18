const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

const PORT = 3000;
const SECRET = "1234"; 

// Stockage en mémoire
let users = [];
let actions = [];

// --- Inscription ---
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ ok: false, message: "Missing fields" });

  const existing = users.find(u => u.email === email);
  if (existing) return res.status(409).json({ ok: false, message: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, name, email, password: hashed };
  users.push(newUser);

  res.status(201).json({ ok: true, message: "User created", user: { id: newUser.id, name, email } });
});

// --- Connexion ---
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ ok: false, message: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ ok: false, message: "Invalid credentials" });

  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: "1h" });
  res.json({ ok: true, token, user: { id: user.id, name: user.name, email: user.email } });
});

// --- Middleware Auth ---
function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ ok: false, message: "No token" });
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ ok: false, message: "Invalid token" });
  }
}

// --- Publier une action ---
app.post("/actions", auth, (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ ok: false, message: "Content required" });
  const action = { id: actions.length + 1, userId: req.user.id, content };
  actions.push(action);
  res.status(201).json({ ok: true, action });
});

// --- Voir ses actions ---
app.get("/actions/me", auth, (req, res) => {
  const myActions = actions.filter(a => a.userId === req.user.id);
  res.json({ ok: true, actions: myActions });
});

// --- Supprimer une action ---
app.delete("/actions/:id", auth, (req, res) => {
  const actionId = parseInt(req.params.id);
  actions = actions.filter(a => !(a.id === actionId && a.userId === req.user.id));
  res.json({ ok: true, message: "Action deleted" });
});

app.listen(PORT, () => console.log(`🚀 API running at http:// 192.168.56.1:${PORT}`));
