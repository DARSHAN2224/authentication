import mongoose from "mongoose"
export const connectDb=async()=>{
    try {
        const conn=await mongoose.connect(process.env.MONGO_URL)
        console.log(`MongoDB connected to ${conn.connection.host}`)
    } catch (error) {
        console.log("error connecting to MongoDB:",error.message);
        process.exit(1)
        
    }
}