import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// --> all of these routes are PREFIXED with /auth
// 'auth/login' is the full path
export const login = async (req: Request, res: Response) => {
  // TODO: If the user exists and the password is correct, return a JWT token
  const { username, password } = req.body;
 // console.log("Incoming request", req.body);

  const user = await User.findOne({ where: { username }});
 // console.log("User found", user);
  // valitate user
  if (!user) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  // validate password
  const validPassword = await bcrypt.compare(password, user.password);
 // console.log("Valid password", validPassword);
  if (!validPassword) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

 // const secret = process.env.JWT_SECRET_KEY as string || '';

  const payload = { username };
  const token = jwt.sign(payload, process.env.JWT_SECRET_KEY as string, { expiresIn: '1h' });
 // console.log("Token", token);
  return res.json({ token });
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
