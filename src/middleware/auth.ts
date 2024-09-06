import { auth } from "express-oauth2-jwt-bearer";
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken"
import User from "../models/user";
 
declare global{
  namespace Express{
    interface Request{
      userId:string;
      auth0Id:string;
    }
  }
}

export const jwtCheck = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
  tokenSigningAlg: 'RS256'
});

export const jwtParse = async(req: Request, res: Response, next: NextFunction)=>{
 //need to  get the access ten from the authorization
 //return status 401 that is unauthorized
  const { authorization } = req.headers;
if(!authorization || !authorization?.startsWith("Bearer ")){
 return res.sendStatus(401);
}
//if we have a valid authorization header we need to get token from the string
//authorization token will be 2nd in the string
//jwt help us to decode the token
const token = authorization.split(" ")[1];
 try{
  const decoded = jwt.decode(token) as jwt.JwtPayload;
//after decoding we get user authId
 const auth0Id = decoded.sub;

 const user = await User.findOne({auth0Id});
 if(!user){
  return res.status(401);
 }
 req.auth0Id = auth0Id as string;
 req.userId = user._id.toString();
 next();
 }
 catch(error){
  return res.sendStatus(401);
 }
}

