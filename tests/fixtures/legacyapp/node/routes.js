// express routes (test fixture)
const { exec } = require("child_process");
app.get("/user", (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
  exec(`convert ${req.query.file} out.png`);
  res.sendFile(req.query.path);
});
function render(msg) { document.getElementById("out").innerHTML = msg; }
