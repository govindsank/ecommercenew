import mongoose from "mongoose"

export default function con(){
    return mongoose.connect(process.env.DB_URI);
}