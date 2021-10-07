require('dotenv').config();

const express = require('express');
const app = express();

const jwt = require('jsonwebtoken');

app.use(express.json());

let refreshTokens = [];

app.post('/token', (req, res)=>{
    // refresh token
    const {token} = req.body
    if(token == null) return res.sendStatus(401);
    if(!refreshTokens.includes(token)) return res.sendStatus(403);
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user)=>{
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({name:user.name})
        res.json({accessToken});
    })
})

app.delete('/logout', (req, res)=>{
    refreshTokens = refreshTokens.filter(token=>token !== req.body.token)
    res.sendStatus(204);
})

app.post('/login',(req, res)=>{
    // aunticate user firs separate video
    const {username} = req.body;
    const user ={
        name: username,
    }
    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    refreshTokens.push(refreshToken)
    res.status(200).json({accessToken: accessToken, refreshToken: refreshToken})

})
function generateAccessToken(user){
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET,
        {expiresIn: '30s'});
}

app.listen(3000,()=>{
    console.log("server started...")
});