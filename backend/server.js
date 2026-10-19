require("dotenv").config();

const express = require("express");
const cors = require("cors");
const pool = require("./db");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/db-test", async (req, res) => {
    try {
        const rows = await pool.query("SELECT 1 AS result");
        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).send("Database connection failed");
    }
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
})
