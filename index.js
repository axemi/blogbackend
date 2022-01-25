require("dotenv").config()
const express = require("express")
const app = express()
const path = require("path")
const port = process.env.PORT || 4000
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const knexconfig = require("./knexfile")[process.env.NODE_ENV || "production"]
const db = require("knex")(knexconfig)
const cors = require("cors")
app.use(cors())
app.use(express.json())
app.get("/", (req, res) => {
    res.send("Connected!")
})
//todo: token expiration and refresh tokens
function authenticateToken(req, res, next) {
    const userid = req.body.userid
    const auth = req.headers["authorization"]
    jwt.verify(auth, process.env.BLOG_ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        if (user.userid !== userid) return res.sendStatus(403)
        req.user = user
        next()
    })
}
app.post("/posts", authenticateToken, async (req, res) => {
    try {
    //get req body with title and content, userid
    let {title, content, userid} = req.body
    //insert into posts table
    await db("posts").insert({userid, title, content})
    //send ok status
    res.sendStatus(200)
    } catch (err) {
        console.log(err)
        res.sendStatus(500)
    }
})
app.put("/posts", authenticateToken, async (req, res) => {
    try {
    //get req body with title and content, userid
    let {title, content, userid, postid, authorid} = req.body
    if (authorid !== userid) return res.sendStatus(403) //only the original author can edit their posts
    //insert into posts table
    await db("posts").update({userid, title, content}).where({id: postid})
    //send ok status
    res.sendStatus(200)
    } catch (err) {
        console.log(err)
        res.sendStatus(500)
    }
})
app.delete("/posts", authenticateToken, async (req, res) => {
    try {
    //get req body with title and content, userid
    let {postid, authorid, userid} = req.body
    if (authorid !== userid) return res.sendStatus(403) //only the original author can edit their posts
    //insert into posts table
    await db("posts").del().where({id: postid})
    //send ok status
    res.sendStatus(200)
    } catch (err) {
        console.log(err)
        res.sendStatus(500)
    }
})
app.get("/posts/:username", async (req, res) => {
    let username = req.params.username
    try {
        let users = await db("users").select().where({username: username})
        if (users.length > 0 ) {
            let posts = await db("posts").select().where({userid: users[0].id})
            let user = {
                first_name: users[0].first_name,
                last_name: users[0].last_name,
                username: users[0].username
            }
            res.json({...user,posts})
        }
    } catch(err) {
        console.log(err)
        res.sendStatus(500)
    }
})
app.get("/posts", async (req, res) => {
    try {
        let posts = await db("posts").select()
        for (let i = 0; i < posts.length; i++) {
            let user = await db("users").select("username").where({id: posts[i].userid})
            posts[i] = {username: user[0].username, ...posts[i]}
        }
        res.json({posts})
    } catch(err) {
        console.log(err)
        res.sendStatus(500)
    }
})
app.post("/login", async (req, res) => {
    try {
        let rows = await db("users").select().where({username: req.body.username})
        if (rows.length <= 0) return res.sendStatus(403)
        let match = await bcrypt.compare(req.body.password, rows[0].password)
        let user = {userid: rows[0].id, first_name: rows[0].first_name, last_name: rows[0].last_name, username: rows[0].username}
        const accessToken = jwt.sign(user,process.env.BLOG_ACCESS_TOKEN_SECRET)
        match ? res.json({...user, accessToken}) : res.sendStatus(403)

    } catch (err) {
        console.log(err)
        res.sendStatus(500)
    }
})
app.post("/users", async (req, res) => {
    try {
        const {first_name, last_name, username} = req.body
        const salt = await bcrypt.genSalt()
        const hash = await bcrypt.hash(req.body.password, salt)
        let row = await db("users").insert({first_name, last_name, username, password: hash, salt}, ["id"])
        console.log(row)
        let user = {userid: row[0].id, first_name, last_name, username}
        const accessToken = jwt.sign(user, process.env.BLOG_ACCESS_TOKEN_SECRET)
        res.json({userid: user.userid, first_name, last_name, username, accessToken})

    } catch (err) {
        console.log(err)
        res.sendStatus(500)
    }
})
app.listen(port, (req, res) => {
    console.log(`listening on port ${port}`)
})