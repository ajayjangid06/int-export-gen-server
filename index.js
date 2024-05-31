const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require('@prisma/client');

const multer = require("multer");
const cors = require('cors');

const cron = require("node-cron");

const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const prisma = new PrismaClient();
const app = express();
const port = process.env.PORT || 4000;
const SECRET_KEY = "your_secret_key";

const cloudinary = require('cloudinary').v2;

const corsOptions = {
  origin: '*', //included origin as true
};

app.use(cors(corsOptions));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
const storage = multer.memoryStorage();
const upload = multer({ storage });

app.get("/", async (req, res) => {
  res.send('hello');
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({
      data: { email, password: hashedPassword },
    });
    res.json(user);
  } 
  catch(err) {
    return res.json({error: err})
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
      res.json({ token });
    } else {
      res.status(401).send('Invalid credentials');
    }
  } 
  catch(err) {
    return res.json({error: err})
  }
});

function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.sendStatus(403);
  try {
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  } 
  catch(err) {
    return res.sendStatus(403);
  }
}

cloudinary.config({ 
  cloud_name: process.env.CLOUD_NAME, 
  api_key: process.env.CLOUD_KEY, 
  api_secret: process.env.CLOUD_SECRET
});


app.post(
  "/upload",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    const { publishAt, imageData } = req.body;
    const userId = req.user.userId;
    const { originalname, mimetype, size } = req.file;
    // const imageBuffer = await sharp(req.file.buffer)
    //   .resize(400, 400)
    //   .png()
    //   .toBuffer();
    try {
      cloudinary.uploader.upload(imageData, {
        resource_type: 'image',
        transformation: [
          { width: 400, height: 400, crop: 'fit' },
          { format: 'png' }
        ]
      }, async (error, result) => {
        if (error) {
          return res.status(500).send('Upload failed.');
        }
  
  
        const image = await prisma.image.create({
          data: {
            url: result.secure_url,
            userId,
            publishAt: new Date(publishAt),
            originalName: originalname,
            mimeType: mimetype,
            size: size,
          },
        });
  
        res.json({image});
      });
    } 
    catch(err) {
      return res.json({error: err});
    }

  }
);

app.get(
  "/my-uploads",
  authenticateToken,
  async (req, res) => {
    const userId = req.user.userId;
    try {
      const images = await prisma.image.findMany({ where: { userId } });
      res.json({images});
    } catch(error) {
      return res.json({error});
    }
  }
);

cron.schedule("* * * * *", async () => {
  try {
    const images = await prisma.image.findMany({
      where: { status: "pending", publishAt: { lte: new Date() } },
    });
    if(images && images.length > 0) {
      for (const image of images) {
        await prisma.image.update({
          where: { id: image.id },
          data: { status: "published" },
        });
      }
    }
  } catch(err) {
    console.log('job failed')
  }
});

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});

app.use(limiter);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
