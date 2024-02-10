import { Router } from "express";
import * as todo from "./request_handler.js";


const router =Router();
router.route("/input").post(todo.input);
router.route("/getTodo").get(todo.getTodo);

export default router