"use strict";

const fs = require("fs");
const http = require("http");
const express = require("express");
const app = express();
const routes = require('./routes/routes');


app.get("/", (req, res, next) => {
    return res.status(200).json({
        status: true,
        status_message: "Hello world!!!"
    });
});

app.use('/api', routes);

const credentials = {
    key: fs.readFileSync("keys/ssl/private.key"),
    cert: fs.readFileSync("keys/ssl/bundle.crt"),
    dhparam: fs.readFileSync("keys/ssl/dh-strong.pem"),
    requestCert: true,
    rejectUnauthorized: false
};

const server = http.createServer( app);

server.listen(3000, () => {
    console.log("Server running at https://localhost:3000/");
});
