const http=require("http");
const {Server}=require("socket.io");
const express=require("express");
const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");
const mongoose=require("mongoose");
require("dotenv").config();
const app=express();
app.use(express.json());
app.use((req,res,next)=>{console.log("Request Received");
                         next(); 
                        });
const SECRET_KEY=process.env.SECRET_KEY;
mongoose.connect(process.env.MONGO_URL,{serverSelectionTimeoutMS:10000}).then(()=>console.log("Connected to MongoDB")).catch((err)=>console.log("Connection failed : "+err));
const userSchema=new mongoose.Schema({
    name:String,
    password:String
});
const documentSchema=new mongoose.Schema({
    title:String,
    content:{type:String,default:""},
    owner:String
});
const User=mongoose.model("User",userSchema);
const Document=mongoose.model("Document",documentSchema);
function verifyToken(req,res,next)
{
    const authHeader=req.headers["authorization"];
    if(!authHeader)
    {
        return res.status(401).send("No token provided");
    }
    else
    {
        const token=authHeader.split(" ")[1];
        jwt.verify(token,SECRET_KEY,(err,decoded)=>
        {
            if(err)
            {
             return res.status(403).send("Invalid or expired token");   
            }
            req.user=decoded;
            next();
        })
    }
}
app.post("/document",verifyToken,async(req,res)=>
{
 const title=req.body.title;
 const owner=req.user.name;
 if(!title)
    {
    return res.status(400).send("Title is required"); 
    }
 const newDoc=new Document({title:title,owner:owner})
 await newDoc.save();
 res.status(201).json(newDoc)
});
app.get("/document/:id",verifyToken,async(req,res)=>{
    const id=req.params.id;
    const doc=await Document.findById(id);
    if(!doc)
    {
        return res.status(404).send("Document not found");
    }
    res.status(200).json(doc);
});
app.get("/documents",verifyToken,async(req,res)=>
{
 const owner=req.user.name;
 const docs=await Document.find({owner:owner},{content:0});
 res.status(200).json(docs);
})
app.get("/",(req,res)=>{res.send("Backend server is running");});
app.post("/user",async(req,res)=>{
    const name=req.body.name;
    const password=req.body.password;
    if(!name || !password)
        {
            res.status(400).send("Name and password is required");
        }
    else{
            const hashpw=await bcrypt.hash(password,10);
            const newUser=new User(
                {
                    name:name,password:hashpw
                });
                await newUser.save();
            res.status(201).send("User created : "+name);
        }
    });
app.get("/users",async(req,res)=>{
        const name=req.query.name;
        if(name)
        {
            const result=await User.find({name:name},{password:0});
            if(result.length===0)
            {
                res.status(404).send("User not found");
            }
            else
            {
                res.status(200).json(result);
            }
        }    
        else
            {
                const allUsers=await User.find({},{password:0});
                res.status(200).json(allUsers);
            }
        });
app.delete("/user/:name",async(req,res)=>{const name=req.params.name;
                                     const result=await User.findOneAndDelete({name:name});
                                     if(result)
                                     {
                                     res.status(200).send("User deleted is : "+name);
                                     }
                                     else
                                     {
                                      res.status(404).send("User not found");
                                     }
});
app.put("/user/:name",async(req,res)=>{const oldname=req.params.name;
                                  const newname=req.body.name;
                                  const result=await User.findOneAndUpdate({name:oldname},{name:newname});
                                  if(result)
                                  {
                                   res.status(200).send("User updated");
                                  }
                                  else
                                  {
                                   res.status(404).send("User not found"); 
                                  }  
});
app.post("/login",async(req,res)=>
{
 const name=req.body.name;
 const password=req.body.password;
 const user=await User.findOne({name:name});
 if(!user)
 {
    return res.status(404).send("User not found");
 }
 const match=await bcrypt.compare(password,user.password);
 if(match)
 {
    const token=jwt.sign({name:user.name},SECRET_KEY,{expiresIn:"1h"});
    res.status(200).json({message:"Login successful",token:token});
 }
 else
 {
    res.status(401).send("Invalid password");
 }
});
app.get("/protected",verifyToken,(req,res)=>
{
 res.status(200).send("Hello "+req.user.name+" ! You are inside a protected route");
});
const server=http.createServer(app);
const io=new Server(server,{cors: {origin:"*"}
});
io.on("connection",(socket)=>{
console.log("User connected : "+socket.id);
socket.on("join-document",async(documentId)=>{
socket.join(documentId);
const doc=await Document.findById(documentId);
socket.emit("load-document",doc.content);
});
socket.on("send-changes",(delta)=>{
socket.broadcast.to(delta.documentId).emit("receive-changes",delta);
});
socket.on("save-document",async(data)=>{
await Document.findByIdAndUpdate(data.documentId,{content:data.content});
});
socket.on("disconnect",()=>{
    console.log("User disconnected : "+socket.id);
})
});
server.listen(5000,() => {
  console.log("Server running on port 5000");
});

