// server.js
// התקנה:  npm init -y && npm install express cors bcryptjs jsonwebtoken
// הרצה:   node server.js

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 4000;
// בפרודקשן חובה להגדיר סוד חזק במשתנה סביבה
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const JWT_EXPIRES_IN = "1Y";
const USERS_FILE = path.join(__dirname, "users.json");

const app = express();
app.use(cors({ origin: "*" })); // כתובת ה-React (Vite)
app.use(express.json());

/* ---------- אחסון משתמשים בקובץ JSON ---------- */
function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  } catch {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

/* ---------- רשימה שחורה לטוקנים שבוצע להם logout ---------- */
const revokedTokens = new Set();

/* ---------- Middleware לאימות JWT ---------- */
function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) return res.status(401).json({ error: "חסר טוקן" });
  if (revokedTokens.has(token)) {
    return res.status(401).json({ error: "הטוקן בוטל, יש להתחבר מחדש" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    req.token = token;
    next();
  } catch {
    res.status(401).json({ error: "טוקן לא תקין או שפג תוקפו" });
  }
}

function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
}

/* ---------- Routes ---------- */

// הרשמה
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "יש למלא שם, אימייל וסיסמה" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "הסיסמה חייבת להכיל לפחות 6 תווים" });
  }

  const users = readUsers();
  const normalizedEmail = email.trim().toLowerCase();

  if (users.some((u) => u.email === normalizedEmail)) {
    return res.status(409).json({ error: "האימייל כבר רשום במערכת" });
  }

  const user = {
    id: Date.now().toString(),
    name: name.trim(),
    email: normalizedEmail,
    passwordHash: await bcrypt.hash(password, 10),
  };
  
  users.push(user);
  writeUsers(users);

  res.status(201).json({
    token: signToken(user),
    user: { id: user.id, name: user.name, email: user.email },
  });
});

// התחברות
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "יש למלא אימייל וסיסמה" });
  }

  const user = readUsers().find((u) => u.email === email.trim().toLowerCase());
  const valid = user && (await bcrypt.compare(password, user.passwordHash));

  if (!valid) {
    return res.status(401).json({ error: "אימייל או סיסמה שגויים" });
  }

  res.json({
    token: signToken(user),
    user: { id: user.id, name: user.name, email: user.email },
  });
});

// התנתקות - מבטל את הטוקן הנוכחי
app.post("/api/logout", authenticate, (req, res) => {
  revokedTokens.add(req.token);
  res.json({ message: "התנתקת בהצלחה" });
});

// נתיב מוגן - פרטי המשתמש המחובר
app.get("/api/me", authenticate, (req, res) => {
  const user = readUsers().find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "משתמש לא נמצא" });
  res.json({ id: user.id, name: user.name, email: user.email });
});

app.listen(PORT, () => {
  console.log(`Server running on port:${PORT}`);
});
