import userModel from "./model/todo.model.js"

export async function input(req,res){
    try {
         let {todoInput}=req.body;
         if(!(todoInput)){
            return res.status(400).json({
                msg:"input field cannt be empty"
            })
         }
        //  let todoExist =await userModel.
        let result= await userModel.create({
            todoInput
        })
        if(result){
        return res.status(201).json({
            msg:"successfull!!"
        })
    }
    } catch (error) {
        console.log(error);
    }
   
}
export async function getTodo(req,res){
    try {
        let {todo}=req.body;
        let result=await userModel.find();
        if(result){
            return res.json(result);
        } 
        return res.status(500).send("error")
    } catch (error) {
        console.log(error);
    }
}