const bcrypt = require('bcryptjs');
const password = process.argv[2];
if (!password || password.length < 12) {
  console.error("Usage: node make-manager-hash.js 'AtLeast12CharactersPassword'");
  process.exit(1);
}
bcrypt.hash(password, 12).then(hash => console.log(hash));
