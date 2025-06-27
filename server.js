const express = require("express");
const AWS = require("aws-sdk");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const dynamoDB = new AWS.DynamoDB.DocumentClient();
const BOOKING_TABLE = process.env.DYNAMODB_TABLE;
const USER_TABLE = process.env.USERS_TABLE;

// 🔒 JWT Auth Middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("No token provided");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(403).send("Invalid token");
  }
}

// 🌐 Routes

// Home
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "home.html"));
});

// Book Laundry Page
app.get("/index", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ✅ Signup
app.post("/signup", async (req, res) => {
  const { username, password, email, phone, location, role } = req.body;

  if (!username || !password || !email || !phone || !location || !role) {
    return res.status(400).send("All fields are required, including role");
  }

  try {
    const existingUser = await dynamoDB.get({
      TableName: USER_TABLE,
      Key: { Username: username },
    }).promise();

    if (existingUser.Item) {
      return res.status(400).send("User already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await dynamoDB.put({
      TableName: USER_TABLE,
      Item: {
        Username: username,
        Password: hashedPassword,
        Email: email,
        Phone: phone,
        Location: location,
        Role: role,
      },
    }).promise();

    res.send("Signup successful");
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).send("Signup failed");
  }
});

// ✅ Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await dynamoDB.get({
      TableName: USER_TABLE,
      Key: { Username: username },
    }).promise();

    if (!result.Item) {
      return res.status(401).send("User not found");
    }

    const user = result.Item;

    const isMatch = await bcrypt.compare(password, user.Password);
    if (!isMatch) {
      return res.status(401).send("Invalid password");
    }

    const token = jwt.sign(
      { username: user.Username, role: user.Role },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token, role: user.Role });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).send("Internal Server Error");
  }
});

// ✅ Book Laundry Route
app.post("/book", authMiddleware, async (req, res) => {
  const { name, phone, date, time, service } = req.body;

  if (!name || !phone || !date || !time || !service) {
    return res.status(400).send("All fields are required");
  }

  const booking = {
    BookingID: Date.now().toString(),
    Name: name,
    Phone: phone,
    Date: date,
    Time: time,
    Service: service,
  };

  try {
    await dynamoDB.put({
      TableName: BOOKING_TABLE,
      Item: booking,
    }).promise();
    res.send("Laundry booking successful");
  } catch (err) {
    console.error("Booking error:", err);
    res.status(500).send("Booking failed");
  }
});

// ✅ Get Booking History for User
app.get("/history/:phone", async (req, res) => {
  const { phone } = req.params;

  const params = {
    TableName: BOOKING_TABLE,
    FilterExpression: "#ph = :phone",
    ExpressionAttributeNames: { "#ph": "Phone" },
    ExpressionAttributeValues: { ":phone": phone },
  };

  try {
    const data = await dynamoDB.scan(params).promise();
    res.json(data.Items);
  } catch (err) {
    console.error("History Fetch Error:", err);
    res.status(500).send("Failed to fetch history");
  }
});

// ✅ Admin: Get All Bookings with Location
// ✅ Admin: Get All Bookings with Location
app.get("/admin/all-bookings", async (req, res) => {
  try {
    const bookingsData = await dynamoDB.scan({
      TableName: BOOKING_TABLE,
    }).promise();

    const bookings = bookingsData.Items;

    if (!bookings || bookings.length === 0) {
      return res.json([]);
    }

    const uniquePhones = [...new Set(bookings.map(b => b.Phone))];
    const userLocationMap = {};

    for (const phone of uniquePhones) {
      const userScan = await dynamoDB.scan({
        TableName: USER_TABLE,
        FilterExpression: "#ph = :phone",
        ExpressionAttributeNames: { "#ph": "Phone" },
        ExpressionAttributeValues: { ":phone": phone }
      }).promise();

      userLocationMap[phone] = userScan.Items[0]?.Location || "Not Provided";
    }

    const bookingsWithLocation = bookings.map(b => ({
      ...b,
      Location: userLocationMap[b.Phone] || "Unknown",
    }));

    res.json(bookingsWithLocation);
  } catch (err) {
    console.error("Admin Booking Fetch Error:", err);
    res.status(500).json({ error: "Error fetching bookings" });
  }
});


// 🚀 Start Server
app.listen(PORT, () => {
  console.log(`✅ Server running at http://3.109.24.123:5000/api/data`);
});
