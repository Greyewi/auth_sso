const express = require('express')
const cors = require('cors')
const app = express()
const port = 6001
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const cookieParser = require('cookie-parser');

const csrf = require('csurf')
const tokenKey = "some complex pass"

const userList = require('./dataBase')

app.use(express.json())
app.use(cors({origin: '*'}))
app.use(cookieParser());



app.use((req, res, next) => {
  const cookieName = 'Authorization'
  const cookie = req.cookies[cookieName];
  if (cookie === undefined) {
    // no: set a new cookie

    console.log('cookie created successfully');
  } else {
    // yes, cookie was already present
    console.log('cookie exists', cookie);
  }
  next(); // <-- important!
});


app.use(async (req, res, next) => {

  if(req.url === '/sign-in'){
    return next()
  }

  if (req.headers.authorization) {
    let token = req.headers.authorization.split(' ')[1]
    const tokenParts = token.split('.')
    const signature = crypto.createHmac('SHA256', tokenKey).update(`${tokenParts[0]}.${tokenParts[1]}`).digest('base64')

    // jwt.verify(token, tokenKey, function(err, decoded) {
    //   // err
    //   // decoded undefined
    // });

    if (signature === tokenParts[2]) {
      next()
    } else {
      res.status(403).send('token is not valid')
    }
  } else {
    res.status(401).send('You need authorization')
  }
})

app.post('/sign-in', async (req, res) => {
  const dataExistUser = userList().find(f => f.login === req.body.login)
  if(!dataExistUser || !dataExistUser.login){
    return res.status(403).send({rows: ["User is empty"]})
  }

  // const isCorrectPassword = await bcrypt.compare(req.body.password, dataExistUser.password)
  // if(!isCorrectPassword) {
  //   return res.status(403).send({rows: ["User is empty"]})
  // }

  const head = Buffer.from(JSON.stringify({alg: 'HS256', typ: 'jwt'})).toString('base64')
  const body = Buffer.from(JSON.stringify({id: dataExistUser.id, login: dataExistUser.login})).toString('base64')
  const signature = crypto.createHmac('SHA256', tokenKey).update(`${head}.${body}`).digest('base64')
  const newToken = `${head}.${body}.${signature}`

  // var token = jwt.sign({id: dataExistUser.id, login: dataExistUser.login}, tokenKey);
  res.cookie('token', newToken, { maxAge: 90000000, httpOnly: false });
  res.status(200).send({token: newToken, login: dataExistUser.login, id: dataExistUser.id})
})

app.use(csrf({ cookie: true }))

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.post('/', (req, res) => {
  res.send('Hello World!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
