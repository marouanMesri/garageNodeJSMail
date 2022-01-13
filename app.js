const express = require("express");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const path = require("path");
const morgan = require("morgan");

const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(morgan("tiny"));
app.use(express.static(path.join(__dirname, "public")));

// GET
app.get("/", (req, res) => {
  res.render("index");
});
app.get("/about", (req, res) => {
  res.render("about");
});
app.get("/contact", (req, res) => {
  res.render("contact");
});

// POST
app.post("/contact/send", (req, res) => {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: "marouanxx@gmail.com",
      pass: "XXX",
    },
  });
  const mailOptions = {
    from: "Marouan Mesri <marouan31@gmail.com>",
    to: "marouan31@gmail.com",
    subject: "Repair automobile",
    text:
      "Message de votre site web provenant de : " +
      req.body.name +
      "ayant pour email : " +
      req.body.email +
      ". Son message est le suivant :" +
      req.body.message,
    html:
      "<p><ul><li> Name :" +
      req.body.name +
      "</li> <li> Email  :" +
      req.body.email +
      "<li> <li> Message :" +
      req.body.message +
      "<li> </ul></p>",
  };
  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log("Error", error);
      res.redirect("/");
    } else {
      console.log("Message sent: " + info.response);
    }
  });
});

app.listen(3000);
console.log("Serveur ouvert sur le port 3000");
