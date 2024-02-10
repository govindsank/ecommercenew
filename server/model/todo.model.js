import mongoose from "mongoose";

const schema =new mongoose.Schema({
    todoInput: {
        type:String,
        required:true,

    }
});
export default mongoose.model.todos || mongoose.model("todo",schema)