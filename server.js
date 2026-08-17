const rateLimit = require("express-rate-limit");
const http = require("http");
const { Server } = require("socket.io");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const crypto=require("crypto");
require("dotenv").config();
const app = express();
app.use(express.json());
const path = require("path");
app.use(express.static(path.join(__dirname, "public")));
app.use((req, res, next) => {
    console.log("Request Received");
    next();
});

const cors = require("cors");
app.use(cors());

const SECRET_KEY = process.env.SECRET_KEY;

mongoose.connect(process.env.MONGO_URL, { serverSelectionTimeoutMS: 10000 })
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.log("Connection failed : " + err));

/* ================== MODELS ================== */

const userSchema = new mongoose.Schema({
    name: { type: String, unique: true },
    password: String
});

const documentSchema = new mongoose.Schema({
    title: String,
    content: { type: String, default: "" },
    owner: String,
    accessToken:{type:String,unique:true,sparse:true}
});

const User = mongoose.model("User", userSchema);
const Document = mongoose.model("Document", documentSchema);

/* ================== MIDDLEWARE ================== */

function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
        return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Invalid or expired token" });
        }

        req.user = decoded;
        next();
    });
}

const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5, // limit each IP to 5 requests per window
    message: {
        message: "Too many login attempts. Try again after 1 minute."
    },
    standardHeaders: true,
    legacyHeaders: false,
});

/* ================== DOCUMENT ROUTES ================== */
app.post("/document/:id/share",verifyToken,async(req,res)=>
{
    try
    {
        const doc=await Document.findById(req.params.id);
        if(!doc)
            return res.status(404).json({message:"Document not found"});
        if(doc.owner!==req.user.name)
            return res.status(403).json({message:"Unauthorized"});
        const token=crypto.randomBytes(16).toString("hex");
        doc.accessToken=token;
        await doc.save();
        const link=`${req.protocol}://${req.get("host")}/editor.html?share=${token}`;
        res.status(200).json({link});
    }
    catch(err)
    {
        res.status(500).json({message:"Server error"});
    }
});
app.get("/share/:token", async (req, res) => {
    try {
        const doc = await Document.findOne({ accessToken: req.params.token });
        if(!doc) return res.status(404).json({ message: "Document not found" });

        // send the document
        res.status(200).json({ 
            id: doc._id, 
            title: doc.title, 
            content: doc.content, 
            owner: doc.owner 
        });
    } catch(err) {
        res.status(500).json({ message: "Server error" });
    }
});
app.post("/document", verifyToken, async (req, res) => {
    const { title } = req.body;
    const owner = req.user.name;

    if (!title) {
        return res.status(400).json({ message: "Title is required" });
    }

    const existingDoc = await Document.findOne({ title, owner });

    if (existingDoc) {
        return res.status(400).json({ message: "Document already exists" });
    }

    const newDoc = new Document({ title, owner });
    await newDoc.save();

    res.status(201).json(newDoc);
});

app.get("/document/:id", verifyToken, async (req, res) => {
    try {
        const doc = await Document.findById(req.params.id);

        if (!doc) {
            return res.status(404).json({ message: "Document not found" });
        }

        if (doc.owner !== req.user.name) {
            return res.status(403).json({ message: "Access denied" });
        }

        res.status(200).json(doc);

    } catch {
        res.status(500).json({ message: "Server error" });
    }
});

app.get("/documents", verifyToken, async (req, res) => {
    const docs = await Document.find(
        { owner: req.user.name },
        { content: 0 }
    );

    res.status(200).json(docs);
});
app.delete("/document/:id",verifyToken,async(req,res)=>
{
    try
    {
     const doc=await Document.findById(req.params.id);
     if(!doc)
     {
        return res.status(404).json({messsage:"Docuement not found"});
     }
     if(doc.owner!==req.user.name)
     {
        return res.status(403).json({message:"Unauthorized"});
     }
     await Document.findByIdAndDelete(req.params.id);
     res.status(200).json({message:"Document Deleted"});
    }
    catch
    {
        res.status(500).json({message:"Server error"});
    }
});

/* ================== USER ROUTES ================== */

app.post("/user", async (req, res) => {
    const { name, password } = req.body;

    if (!name || !password) {
        return res.status(400).json({ message: "Name and password is required" });
    }

    if (password.length < 6) {
        return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const existingUser = await User.findOne({ name });

    if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
    }

    const hashpw = await bcrypt.hash(password, 10);

    const newUser = new User({
        name,
        password: hashpw
    });

    await newUser.save();

    res.status(201).json({ message: "User created successfully" });
});

app.get("/users", async (req, res) => {
    const { name } = req.query;

    if (name) {
        const result = await User.find({ name }, { password: 0 });

        if (result.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        return res.status(200).json(result);
    }

    const allUsers = await User.find({}, { password: 0 });
    res.status(200).json(allUsers);
});

app.delete("/user/:name", verifyToken, async (req, res) => {
    if (req.user.name !== req.params.name) {
        return res.status(403).json({ message: "Unauthorized" });
    }

    const result = await User.findOneAndDelete({ name: req.params.name });

    if (!result) {
        return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ message: "User deleted" });
});

app.put("/user/:name", verifyToken, async (req, res) => {
    if (req.user.name !== req.params.name) {
        return res.status(403).json({ message: "Unauthorized" });
    }

    const result = await User.findOneAndUpdate(
        { name: req.params.name },
        { name: req.body.name }
    );

    if (!result) {
        return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ message: "User updated" });
});

/* ================== LOGIN ================== */

app.post("/login",loginLimiter,async (req, res) => {
    const { name, password } = req.body;

    const user = await User.findOne({ name });

    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
        return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
        { name: user.name },
        SECRET_KEY,
        { expiresIn: "1h" }
    );

    res.status(200).json({
        message: "Login successful",
        token
    });
});

/* ================== SOCKET.IO ================== */

const server = http.createServer(app);

const io = new Server(server, {
    cors: { origin: "*" }
});

io.on("connection", (socket) => {
    console.log("User connected:", socket.id);

    const token = socket.handshake.auth.token;

    if (!token) return socket.disconnect();

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        socket.user = decoded;
    } catch {
        return socket.disconnect();
    }

    socket.on("join-document", async ({documentId,shareToken}) => {
        const doc = await Document.findById(documentId);

        if (!doc) return socket.emit("error", "Document not found");
        const isOwner=doc.owner===socket.user.name;
        const isSharedUser=shareToken && doc.accessToken===shareToken;
        if(!isOwner && !isSharedUser)
        {
            return socket.emit("error","Access denied")
        }
        socket.join(documentId);
        socket.documentId = documentId;

        socket.emit("load-document", doc.content);
    });
    socket.on("typing",()=>{
        if(!socket.documentId)
            return;
        socket.broadcast.to(socket.documentId).emit("user-typing",{
            name:socket.user.name
        });    
    });
    socket.on("send-changes", (data) => {
        if (!socket.documentId) return;

        socket.broadcast
            .to(socket.documentId)
            .emit("receive-changes", data);
    });

    socket.on("save-document", async (data) => {
        if (!socket.documentId) return;

        await Document.findByIdAndUpdate(
            socket.documentId,
            { content: data.content }
        );
    });

    socket.on("disconnect", () => {
        console.log("User disconnected:", socket.id);
    });
});

/* ================== START SERVER ================== */

server.listen(5000,"0.0.0.0",() => {
    console.log("Server running on port 5000");
});