import express from "express"
import dotenv from "dotenv"
import path from "path"
import cors from "cors"


import con from "./connection.js"
import router from "./router.js"
import { error } from "console"

dotenv.config();

const port =process.env.VITE_PORT;
const app= express();

app.use(cors());
app.use(express.json({
    limit:"10mb"
}))
app.use(express.static(path.resolve("./dist")));
app.use("/",router);
app.get("/*",(_req,res)=>{
    return res.sendFile(path.resolve("./dist/index.html"));
})
app.all("/*",(_req,res)=>{
    return res.status(404).json({
        msg:"not Found!!"
    })
})
con().then(()=>{
    app.listen(port,(error)=>{
        if(error){
            return console.log(error);
        }
        console.log(`server started at port:${port}`);
    })
})
.catch(error=>{
    console.log(error);
})
