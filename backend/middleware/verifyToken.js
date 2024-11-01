import jwt from 'jsonwebtoken';

export const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).send({success: false, message: 'Unauthorized Access.- no token provided' })
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if(!decoded){
            return  res.status(401).send({success: false, message: 'Unauthorized Access- invalid token.'});
        }
        req.userId=decoded.userId;
        next();
    } catch (error) {
        console.log('verifyToken error', error);
        return res.status(500).send({ success: false, message: 'Internal Server Error.'})
    }
};

