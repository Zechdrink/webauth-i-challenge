const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs'); 
const cors = require('cors');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);



const Users = require('./users/userModel.js');
const db = require('./database/dbConfig.js');

const server = express();

const sessionConfig = {
  name: 'chocolateChip',
  secret: 'keep it secret, keep it safe',
  cookie: {
    maxAge: 1000 * 60 * 60, //in miliseconds
    secure: false,
  },
httpOnly: true, 
resave: false,
saveUninitialize: false,
store: new KnexSessionStore({
  knex: db,
  tablename: 'sessions',
  sidfieldname: 'sid',
  createTable: true,
  clearInterval: 1000 * 60 * 60
}),
}

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));

server.get('/', (req, res) => {
  res.send("I is awake...");
});


server.post('/api/register', (req, res) => {
  let user = req.body;

  const hash = bcrypt.hashSync(user.password, 7);
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.username = user.username;
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/users',restricted, only('bobo'), (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.get('/api/logout', (req, res, next) => {
  if(req.session){
    req.session.destroy(err => {
      if(err){
        res.send('Im afraid you will not be leaving')
      } else {
        res.send('ba bye')
      }
    })
      }
      else {
        res.end()
      }
})

function only(username) {
  return function (req, res, next) {
    if(req.headers.username === username){
      next();
    } else {
      res.status(403).json({ message: `you not ${username}` })
    }
  };
}

function restricted(req, res, next) {

  if(req.session && req.session.username){
    next();
  } else {
    res.status(401).json({ message: 'you shall not..... PASSSSSSSSS!'})
  }
}

// BEFORE COOKIES EXISTED EXAMPLE of old restricted
// function restricted(req, res, next) {
//   const {username, password} = req.headers;

//   if(username && password ){
//     Users.findBy({ username })
//       .first()
//       .then( user => {
//         if(user && bcrypt.compareSync(password, user.password)) {
//           next();
//         } else {
//           res.status(401).json({ message: 'you no passy' });
//         }
//       })
//       .catch(error => {
//         res.status(500).json(error);
//       });
//   } else {
//     res.status(401).json({ message: 'you need to provide credentials'})
//   }
// }


server.listen(5000, () => console.log(`\n** Running on http://localhost:5000 **\n`));
