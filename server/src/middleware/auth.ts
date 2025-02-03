import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

// Go over with tutor
export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  // TODO: verify the token exists and add the user data to the request object
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1]; // Extract token after "Bearer"

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    // Verify the token and extract user data
    const secret = process.env.JWT_SECRET_KEY as string;
    const decoded = jwt.verify(token, secret) as JwtPayload;
    
    // Attach user data to request object for use in protected routes
    req.user = decoded;

    return next(); // Move to the next middleware or route handler
  } catch (error) {
    console.error(error);
    return res.status(403).json({ message: 'Invalid or expired token.' });
  }
};
