require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 5432,
});

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "public/uploads/");
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + path.extname(file.originalname);
        cb(null, uniqueName);
    },
});


const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
        cb(null, true);
    } else {
        cb(new Error("Only image files are allowed!"), false);
    }
};

const upload = multer({ storage, fileFilter });


function checkUser(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    res.locals.userId = null;
    return next();
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.locals.userId = decoded.userId;
  } catch (err) {
    res.locals.userId = null;
  }
  next();
}

app.use(checkUser);

function requireJWT(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.redirect("/login");
  }
}


app.get("/signup", (req, res) => res.render("signup", { error: null }));

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const userCheck = await pool.query(
      "SELECT id FROM users WHERE email = $1 OR username = $2",
      [email, username]
    );
    if (userCheck.rows.length > 0) {
      return res.render("signup", { error: "Username or email already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3) RETURNING id`,
      [username, email, passwordHash]
    );

    const token = jwt.sign({ userId: result.rows[0].id }, JWT_SECRET, { expiresIn: "30d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.render("signup", { error: "Something went wrong" });
  }
});

app.get("/login", (req, res) => res.render("login", { error: null }));

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.render("login", { error: "Invalid email or password" });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "30d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.render("login", { error: "Something went wrong" });
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});


app.get("/", async (req, res) => {

  try {
    res.send("Instagram-lite running");
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});



app.get("/profile/edit", requireJWT, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, bio, avatar_url, is_private FROM users WHERE id = $1",
      [req.userId]
    );
    if (result.rows.length === 0) return res.redirect("/login");

    res.render("edit-profile", { user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});


app.post("/profile/edit", requireJWT, upload.single("avatar"), async (req, res) => {
  const { bio } = req.body;
  const isPrivate = Boolean(req.body.is_private);

  try {
    const currentRes = await pool.query(
      "SELECT username, avatar_url FROM users WHERE id = $1",
      [req.userId]
    );
    const currentUser = currentRes.rows[0];

    if (req.file) {
      const newAvatarUrl = `/uploads/${req.file.filename}`;

      await pool.query(
        "UPDATE users SET bio = $1, avatar_url = $2, is_private = $3 WHERE id = $4",
        [bio, newAvatarUrl, isPrivate, req.userId]
      );

      
      if (currentUser.avatar_url && currentUser.avatar_url !== "/uploads/default-avatar.png") {
        const oldPath = path.join(__dirname, "public", currentUser.avatar_url);
        fs.unlink(oldPath, (err) => {
          if (err) console.error("Failed to delete old avatar:", err);
        });
      }
    } else {
      await pool.query(
        "UPDATE users SET bio = $1, is_private = $2 WHERE id = $3",
        [bio, isPrivate, req.userId]
      );
    }

    res.redirect(`/profile/${currentUser.username}`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});


app.get("/profile/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const userRes = await pool.query(
      "SELECT id, username, bio, avatar_url, is_private, created_at FROM users WHERE username = $1",
      [username]
    );

    if (userRes.rows.length === 0) {
      return res.status(404).send("User not found");
    }

    const profileUser = userRes.rows[0];

    
    const countsRes = await pool.query(
      `SELECT 
        COUNT(*) FILTER (WHERE following_id = $1 AND status = 'accepted') AS follower_count,
        COUNT(*) FILTER (WHERE follower_id = $1 AND status = 'accepted') AS following_count
       FROM follows`,
      [profileUser.id]
    );

    
    let followStatus = null;
    if (res.locals.userId && res.locals.userId !== profileUser.id) {
      const followRes = await pool.query(
        "SELECT status FROM follows WHERE follower_id = $1 AND following_id = $2",
        [res.locals.userId, profileUser.id]
      );
      if (followRes.rows.length > 0) {
        followStatus = followRes.rows[0].status;
      }
    }

    
    const postsRes = await pool.query(
      "SELECT * FROM posts WHERE user_id = $1 ORDER BY created_at DESC",
      [profileUser.id]
    );

    res.render("profile", {
      profileUser,
      posts: postsRes.rows,
      followerCount: parseInt(countsRes.rows[0].follower_count),
      followingCount: parseInt(countsRes.rows[0].following_count),
      followStatus,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});