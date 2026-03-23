// Example vulnerable JavaScript file - DO NOT USE IN PRODUCTION

// SEC-001: Hardcoded API key
const API_KEY = "sk-live-abc123def456ghi789jkl012mno345pqr678";
const DB_PASSWORD = "SuperSecret123!";
const JWT_SECRET = "mysupersecretjwtkey";

// SEC-003: Dangerous eval() usage
function parseUserInput(input) {
  return eval(input);
}

// SEC-004: SQL injection vulnerability
function getUser(userId) {
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return db.execute(query);
}

function searchProducts(term) {
  const sql = "SELECT * FROM products WHERE name = '" + term + "'";
  return db.query(sql);
}

// SEC-005: innerHTML usage (XSS risk)
function renderComment(comment) {
  document.getElementById("output").innerHTML = comment;
}

function updateProfile(userData) {
  profileDiv.innerHTML = userData.bio;
}

// Normal code
function add(a, b) {
  return a + b;
}
