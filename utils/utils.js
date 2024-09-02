const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const PUBLIC_KEY = process.env.PUBLIC_KEY || fs.readFileSync(path.join(__dirname, "public_key.pem"), "utf8");
const PRIVATE_KEY = process.env.PRIVATE_KEY || fs.readFileSync(path.join(__dirname, "private_key.pem"), "utf8");

const AES_KEY = crypto.randomBytes(32).toString("hex");
const AES_IV = crypto.randomBytes(16).toString("hex");