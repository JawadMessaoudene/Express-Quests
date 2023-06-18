const argon2 = require("argon2");
const jwt = require("jsonwebtoken");

const hashingOptions = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 5,
  parallelism: 1,
}

const hashPassword = async (req, res, next) => {
  try {
    let hash = await argon2.hash(req.body.password, hashingOptions)

      req.body.hashedPassword = hash;
      delete req.body.password;
      next();
    } catch{(err) => {
      console.error(err);
      res.sendStatus(500);
    }};
};

const verifyPassword = async (req, res) => {
  
  try {
    const password = req.user.hashedPassword
    if (await argon2.verify(password, req.body.hashedPassword)) {
      const payload = { sub: req.user.id }

      const token = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });
      delete req.user.hashedPassword;
      res.send( { token, user: req.user })
    } else {
      res.sendStatus(401);
    }
  }
  catch(err) {
    console.error(err)
    res.sendStatus(500);
  };
};

const verifyToken = (req, res, next) => {
  try{
    const authorizantioHeader = req.get("Authorization");
    if(authorizantioHeader == null) {
      throw new Error("Authorization header is missing")
    }

    const [type, token] = authorizantioHeader.split(" ");

    if (type !== "Bearer") {
      throw new Error("Authorization header has not the 'Bearer' type");
    }

    req.payload = jwt.verify(token, process.env.JWT_SECRET);

    next();
  } catch (err) {
    console.error(err)
    res.sendStatus(401);
  }
}

module.exports = {
  hashPassword,
  verifyPassword,
  verifyToken,
};