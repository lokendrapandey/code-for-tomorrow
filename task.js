const mongoose = require("mongoose");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

mongoose.connect("mongodb://127.0.0.1/Task");

const jwtKey = "lokendrapandey";

const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    password: String
});

const User = mongoose.model("User", userSchema);


app.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ firstName, lastName, email, password: hashedPassword });
        await user.save();
        res.status(201).send("User registered successfully");
    } catch (error) {
        res.status(400).send(error.message);
    }
});



app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user._id }, jwtKey, { expiresIn: "1h" });
            res.json({ user: { firstName: user.firstName, lastName: user.lastName, email: user.email }, token });
        } else {
            res.status(400).send("Invalid email or password");
        }
    } catch (error) {
        res.status(500).send(error.message);
    }
});

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (token) {
        jwt.verify(token, jwtKey, (err, decoded) => {
            if (err) {
                return res.status(403).send("Invalid token");
            }
            req.userId = decoded.id;
            next();
        });
    } else {
        res.status(403).send("Token required");
    }
};

app.get('/user', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select("-password");
        res.json(user);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'email',
        pass: 'password'
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send("User with this email does not exist");
        }

        const token = jwt.sign({ id: user._id }, jwtKey, { expiresIn: "5m" });
        const resetLink = `http://yourfrontend.com/reset-password?token=${token}`;
        
        await transporter.sendMail({
            from: 'your-email@gmail.com',
            to: email,
            subject: 'Password Reset',
            html: `<p>Click <a href="${resetLink}">here</a> to reset your password. This link will expire in 5 minutes.</p>`
        });

        res.send("Password reset link sent to your email");
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const decoded = jwt.verify(token, jwtKey);
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.findByIdAndUpdate(decoded.id, { password: hashedPassword });
        res.send("Password updated successfully");
    } catch (error) {
        res.status(400).send("Invalid or expired token");
    }
});




app.listen(5000, ()=>{
    console.log('server is running on port 5000');
})


















// const { default: mongoose } = require("mongoose");
// const express = require("express");
// mongoose.connect("mongodb://127.0.0.1/Task");

// const jwt = require('jsonwebtoken')
// const jwtKey = "lokendrapandey";

// const userSchema = new mongoose.Schema({
//     firstname:String,
//     lastname:String,
//     emai:String,
//     password:String
// })

// const dbModel = mongoose.model("user",userSchema);

// const app = express();
// app.use(express.json());

// app.post('/register', async (req,resp)=>{
//     try {
//         let data = new dbModel(req.body);
//         let result = await data.save();
//         resp.send(result);
//         console.log(result);
//     } catch (error) {
//         resp.status(500).send(error);
//     }
// });

// app.post('/login', async (req,resp)=>{
//     try {
//         let user = await dbModel.findOne(req.body).select("-password")
//         if(user){
//             jwt.sign({dbModel}, jwtKey, {expiresIn:"1h"},(err,token)=>{
//                 if(err){
//                     resp.send({result : "something went wrong , please try again later"})
//                 }
//                 resp.send({user,auth:token})
//             })
            
//         }
//         else{
//             resp.send({result:"no user found"});
//         }
//     } catch (error) {
//         resp.status(500).send(error)
//     }
// })


// app.get('/get', async (req,resp)=>{
//     try{
//        let data = await dbModel.find();
//         resp.send(data);
//     } catch (error){
//         resp.status(500).send(error);
//     }


// })

app.listen(5000, ()=>{
    console.log('server is running on port 5000');
})