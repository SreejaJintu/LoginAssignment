const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const userdata = require('./models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const PORT = process.env.PORT || 8080;

const app = express();
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());

mongoose.connect("mongodb://127.0.0.1:27017/newdb");

const verifyUser = (req, res, next) => {
    const token = req.cookies.token; 
    console.log("Token:", token);

    if (!token) {
        return res.json("Token not available");
    }

    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
        if (err) {
            return res.json("Not Authorized user");
        }
        next();
    });
};

app.get('/', (req, res) => {
    res.send('server started');
});

app.get('/home', verifyUser, (req, res) => {
    return res.json("Success");
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    userdata.findOne({ username: username })
        .then(user => {
            if (user) {
                bcrypt.compare(password, user.password, (err, response) => {
                    if (response) {
                        const token = jwt.sign({ username: user.username }, "jwt-secret-key");
                        res.cookie("token", token, { httpOnly: true });
                        res.json("Success");
                    } else {
                        res.json("Wrong password");
                    }
                });
            } else {
                res.json("No record found");
            }
        });
});

app.post('/submit', (req, res) => {
    try {
        const { username, email, password } = req.body;
        bcrypt.hash(password, 10)
            .then(hash => {
                userdata.create({ username, email, password: hash })
                    .then(user => res.json(user))
                    .catch(err => res.json(err));
            });
    } catch (err) {
        res.json(err);
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on ${PORT}`);
});
