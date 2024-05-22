const sqlite3 = require("sqlite3")
const scryptMcf = require('scrypt-mcf')
const { hash, verify } = require('scrypt-mcf');

//########################### DATABASE CONNECTION ###############################################

const db = new sqlite3.Database('./users.db', sqlite3.OPEN_READWRITE, (err) => {
	if (err) return console.error(err.message);

	console.log("Connection successful");
});

//########################### DATABASE CONNECTION ###############################################


// ########################## SELECT STATEMENT ##################################################

/*sql = `SELECT * FROM user WHERE username = ?`;

db.get(sql, ['walrus'], (err, row) => {
	if (err) { console.error(err.message) };
    	if (!row) { return done(null, false) };

    	console.log(row.password);
});*/

// ############################# INSERT VALUE ####################################################


//db.run('CREATE TABLE users(name TEXT,age INT)');

async function addUser(username, password) {

	const myhash = await hash(password, { derivedKeyLength: 64, scryptParams: { logN: 20, r: 8, p: 2 } });

	db.run('INSERT INTO user(username, password) VALUES(?, ?)', [username,myhash], (err) => {
		if(err) {
			return console.log(err.message);
		}
		console.log('Row was added to the table: ${this.lastID}');
	})

}

addUser('walrus', 'walrus');


// ############################### DELETE VALUE ###################################################


/*db.run('DELETE FROM user WHERE username=(?);', ['walrus'], (err) => {
	if(err) {
		return console.log(err.message); 
	}
	console.log('Row deleted: ${this.username}');
})*/

