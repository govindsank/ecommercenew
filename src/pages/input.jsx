import React from "react";
import { useFormik } from 'formik';
import { useNavigate, Link } from "react-router-dom";

import axios from "axios";
import toast from "react-hot-toast";

function InputTodo() {
    const navigate = useNavigate();
    const formik = useFormik({
        initialValues: {
            todoInput: "" 
        },
        onSubmit: async (values) => {
            let responsePromise = axios.post("http://localhost:3000/input", values);
            toast.promise(responsePromise, {
                loading: "Success....",
                success: (res) => {
                    navigate("/");
                    return res.data.msg;
                },
                error: (res) => res.response.data.msg
            })
        }
        
    });
    return (
        <>
            <div className="container-fluid">

                <form className="Todo" onSubmit={formik.handleSubmit}>

                    <input {...formik.getFieldProps("todoInput")} className="todoInput" type="text" name="todoInput" id="todoInput" placeholder="todoInput" /><br />
                    <input type="submit" className="submit" value="submit" />

                </form>
                <div className="todo"></div>

            </div>
        </>
    )
}
export default InputTodo;









// import React from "react";
// import {useFormik} from 'formik'
// import { useNavigate,Link } from "react-router-dom";


// import axios from "axios";
// import toast from "react-hot-toast";

// function InputTodo(){
//     const navigate=useNavigate();
//     const formik=useFormik({
//         initalValues:{
//             Todo:""
//         },
//         onSubmit: async (values)=>{
//             let responsePromise =axios.post("/input",values);
//             toast.promise(responsePromise,{
//                 loading:"Success....",
//                 success:(res)=>{
//                     navigate("/");

//                     return res.data.msg;
//                 },
//                 error:(res)=> res.response.data.msg
//             })
//         }
//     });
//     return(
//         <>
//         <div className="container-fluid">

//             <form className="Todo" onSubmit={formik.handleSubmit}>

//                 <input {...formik.getFieldProps("todoInput")}className="todoInput" type="text"name="todoInput"id="todoInput"placeholder="todoInput"/><br/>
//                 <input type="submit" className="submit" value="submit" />

//             </form>

//         </div>
//         </>
//     )
// }
// export default InputTodo