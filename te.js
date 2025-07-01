const bcrypt = require("bcryptjs")
const salt = bcrypt.genSaltSync(12); // 자동 생성 (cost 12)
console.log(111, salt)