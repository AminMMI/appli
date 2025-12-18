const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/user.js");

const router = express.Router();
const JWT_SECRET = "supersecret"; // à mettre dans .env
const JWT_MAX_AGE = "1h";

// --- Inscription ---
router.post("/signup", async (req, res) => {
  console.log("🟢 [SIGNUP] Requête reçue");
  console.log("📥 Body reçu :", req.body);

  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    console.log("🔴 [SIGNUP] Champs manquants", { name, email, password });
    return res.status(400).json({ ok: false, message: "Champs manquants" });
  }

  try {
    console.log("🟡 [SIGNUP] Recherche utilisateur existant :", email);
    const existing = await User.findOne({ email });

    if (existing) {
      console.log("🟠 [SIGNUP] Utilisateur déjà existant :", email);
      return res
        .status(409)
        .json({ ok: false, message: "Utilisateur déjà existant" });
    }

    console.log("🟡 [SIGNUP] Création nouvel utilisateur");
    const user = new User({ name, email, password });

    console.log("🟡 [SIGNUP] Sauvegarde en base...");
    await user.save();

    console.log("✅ [SIGNUP] Utilisateur enregistré :", user._id);

    console.log("🟡 [SIGNUP] Génération du token JWT");
    const token = jwt.sign(
      { id: user._id },
      JWT_SECRET,
      { expiresIn: JWT_MAX_AGE }
    );

    console.log("✅ [SIGNUP] Inscription OK");

    return res.status(201).json({
      ok: true,
      user: { id: user._id, name, email },
      token,
    });

  } catch (err) {
    console.error("❌ [SIGNUP] Erreur serveur :", err);
    return res.status(500).json({ ok: false, message: "Erreur serveur" });
  }
});


// --- Connexion ---
router.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ ok: false, message: "Champs manquants" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ ok: false, message: "Identifiants invalides" });

    const match = await user.comparePassword(password);
    if (!match) return res.status(401).json({ ok: false, message: "Identifiants invalides" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_MAX_AGE });

    res.json({ ok: true, user: { id: user._id, name: user.name, email }, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: "Erreur serveur" });
  }
});

module.exports = router;
