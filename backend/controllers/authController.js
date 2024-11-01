import { User } from "../models/User.js";
import bcrypt from "bcryptjs";
import { generateVerificationCode } from "../utils/generateVerificationCode.js";
import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";
import { sendVerificationEmail,sendWelcomeEmail,sendResetPasswordEmail,sendResetSuccessEmail } from "../helpers/emails.js";
import crypto from "crypto"

export const signup = async (req, res) => {
    const { email, password, name } = req.body;
    try {
        if (!email || !password || !name) {
            throw new Error('Please provide all the required fields');
        }
        const userAlreadyExists = await User.findOne({ email });
        if (userAlreadyExists) {
            return res.status(400).json({ success: false,message: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10)
        const verificationToken=generateVerificationCode();
        const user = new User({ 
            email,
            password: hashedPassword, 
            name,
            verificationToken,
            verificationTokenExpiresAt:  Date.now() + 24*60*60*1000, // 24 hours in milliseconds

         })
         await user.save();

         //jwt token generation and validation
         generateTokenAndSetCookie(res, user._id);

         sendVerificationEmail(user.name,user.email,verificationToken)

         res.status(200).json({ success: true, message: 'User successfully created',user :{
            ...user._doc,password:undefined
         }})

    } catch (error) {
        console.log("error in signup",error);
        
        res.status(500).json({ success: false, message: error.message })
    }
}

export const verifyEmail = async (req, res) => {
    const {code}=req.body;
    try {
        const user= await  User.findOne({ 
            verificationToken: code,
            verificationTokenExpiresAt: { $gt:  Date.now() }
         })
         
         if (!user){
            return res.status(400).json({ success: false, message: 'Invalid or expired verification code' })
         }
         user.isVerified=true;
         user.verificationToken=undefined;
         user.verificationTokenExpiresAt= undefined
         await  user.save();
         await sendWelcomeEmail(user.name,user.email);
         res.status(200).json({ 
            success: true,
             message: 'Email successfully verified',
             user:{
                ...user._doc,
                password:-9999
            }
        })
    } catch (error) {
        logger.error("Error in verifyEmail", error);
        res.status(500).json({ success: false, message:"server error" })

    }
}

export const login = async (req, res) => {
const { email, password}=req.body;
try {
    const user=await User.findOne({ email });
    if (!user){
        return res.status(400).json({ success: false, message: "Invalid email or password" })
    }
    const isPasswordVaild=await bcrypt.compare(password, user.password)
    if (!isPasswordVaild){
        return  res.status(400).json({ success: false, message: "Invalid email or password" })
    }
    generateTokenAndSetCookie(res, user._id);
    user.lastLogin = new Date();
    await user.save();
    res.status(200).json({ 
        success: true, 
        message: "User successfully logged in", 
        user:{
            ...user._doc,
            password:undefined

        }
    });
} catch (error) {
    console.log("error in login", error);
    res.status(500).json({ success: false, message: error.message })
}
}

export const logout = async (req, res) => {
res.clearCookie("token");
res.status(200).json({ success: true, message:"User successfully logged out" })
}

export const forgotPassword=async (req, res)=>{
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user){
            return res.status(400).json({ success: false, message:"Invalid email" })
        }
        //Generate reset token
        const resetToken=crypto.randomBytes(20).toString('hex');
        const resetTokenExpiresAt=Date.now()+1*60*60*1000;// 1 hours in milliseconds
        user.resetPasswordToken=resetToken;
        user.resetPasswordExpiresAt=resetTokenExpiresAt;
        await user.save();
        //send email
        await sendResetPasswordEmail(user.name,email,`${process.env.CLIENT_URL}/reset-password/${resetToken}`);
        res.status(200).json({ success: true, message:"Reset token successfully sent to user email address" })
    } catch (error) {
        console.log("Error in forgot password", error);
        return res.status(500).json({ success: false, message: error.message })
        
    }
}

export const resetPassword=async (req, res)=>{
try {
    const {token}=req.params;
    const {password}=req.body;

    const user=await  User.findOne({ resetPasswordToken: token, resetPasswordExpiresAt: { $gt:  Date.now() } })
    if  (!user){
        return res.status(400).json({ success: false, message:"Invalid or expired reset token" }   )
    };

    const hashedPassword=await bcrypt.hash(password, 10);
    user.password=hashedPassword;
    user.resetPasswordToken=undefined;
    user.resetPasswordExpiresAt=undefined;

    await user.save();
    sendResetSuccessEmail(user.name,user.email);
    res.status(200).json({ success: true, message:"User password successfully reset" }  );
} catch (error) {
    console.log("Error in resetPassword", error);
    res.status(500).json({ success: false, message: error.message});
    
}}

export const checkAuth=async (req, res)=>{
    try {
        const user=await User.findById(req.userId).select("-password")
        if (!user){return res.status(400).json({ success: false, message:"User not found" })};
        res.status(200).json({ success: true, user});
    } catch (error) {
        console.log("Error in checkAuth", error);
        return res.status(500).json({ success: false, message: error.message });
        
    }
}