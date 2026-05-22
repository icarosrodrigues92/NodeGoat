const bcrypt = require("bcrypt-nodejs");

/* The UserDAO must be constructed with a connected database object */
function UserDAO(db) {

    "use strict";

    /* If this constructor is called without the "new" operator, "this" points
     * to the global object. Log a warning and call it correctly. */
    if (false === (this instanceof UserDAO)) {
        console.log("Warning: UserDAO constructor called without 'new' operator");
        return new UserDAO(db);
    }

    const usersCol = db.collection("users");

    this.addUser = (userName, firstName, lastName, password, email, callback) => {
        // Fix for A1 - NoSQL Injection: Validate input types AND content to prevent operator injection
        // Attackers could send {"userName": {"$ne": null}} to bypass validations
        if (typeof userName !== 'string' || typeof password !== 'string') {
            return callback(new Error('Invalid input: userName and password must be strings'), null);
        }
        
        // Validate userName format: alphanumeric, underscore, dash (max 50 chars)
        const userNamePattern = /^[a-zA-Z0-9_-]{1,50}$/;
        if (!userNamePattern.test(userName)) {
            return callback(new Error('Invalid userName format: only alphanumeric, underscore, and dash allowed'), null);
        }
        
        // Validate password strength: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit
        const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
        if (!passwordPattern.test(password)) {
            return callback(new Error('Invalid password: min 8 chars with uppercase, lowercase, and digit'), null);
        }

        // Create user document
        const user = {
            userName,
            firstName,
            lastName,
            benefitStartDate: this.getRandomFutureDate(),
            // Fix for A2-1 - Broken Auth
            // Store password safely using bcrypt one-way encryption with salt hashing
            password: bcrypt.hashSync(password, bcrypt.genSaltSync())
        };

        // Add email if set
        if (email) {
            user.email = email;
        }

        this.getNextSequence("userId", (err, id) => {
            if (err) {
                return callback(err, null);
            }
            console.log(typeof(id));

            user._id = id;
            usersCol.insert(user, (err, result) => !err ? callback(null, result.ops[0]) : callback(err, null));
        });
    };

    this.getRandomFutureDate = () => {
        const today = new Date();
        const day = (Math.floor(Math.random() * 10) + today.getDay()) % 29;
        const month = (Math.floor(Math.random() * 10) + today.getMonth()) % 12;
        const year = Math.ceil(Math.random() * 30) + today.getFullYear();
        return `${year}-${("0" + month).slice(-2)}-${("0" + day).slice(-2)}`;
    };

    this.validateLogin = (userName, password, callback) => {
        // Fix for A1 - NoSQL Injection: Validate input types AND content
        // Prevent attackers from sending {"$ne": null} as userName
        if (typeof userName !== 'string' || typeof password !== 'string') {
            const error = new Error('Invalid username and/or password');
            error.invalidPassword = true;
            return callback(error, null);
        }
        
        // Validate userName format: alphanumeric, underscore, dash (max 50 chars)
        const userNamePattern = /^[a-zA-Z0-9_-]{1,50}$/;
        if (!userNamePattern.test(userName)) {
            const error = new Error('Invalid username and/or password');
            error.invalidPassword = true;
            return callback(error, null);
        }

        // Helper function to compare passwords
        const comparePassword = (fromDB, fromUser) => {
            // Fix for A2-Broken Auth
            // Use bcrypt to securely compare hashed passwords
            return bcrypt.compareSync(fromUser, fromDB);
        };

        // Callback to pass to MongoDB that validates a user document
        const validateUserDoc = (err, user) => {

            if (err) return callback(err, null);

            if (user) {
                if (comparePassword(password, user.password)) {
                    callback(null, user);
                } else {
                    const invalidPasswordError = new Error("Invalid password");
                    // Set an extra field so we can distinguish this from a db error
                    invalidPasswordError.invalidPassword = true;
                    callback(invalidPasswordError, null);
                }
            } else {
                const noSuchUserError = new Error("User: " + user + " does not exist");
                // Set an extra field so we can distinguish this from a db error
                noSuchUserError.noSuchUser = true;
                callback(noSuchUserError, null);
            }
        };

        usersCol.findOne({
            userName: userName
        }, validateUserDoc);
    };

    // This is the good one, see the next function
    this.getUserById = (userId, callback) => {
        // Fix for A1 - NoSQL Injection: Validate and parse userId with strict range
        const parsedId = parseInt(userId, 10);
        if (isNaN(parsedId) || parsedId < 0 || parsedId > 999999) {
            return callback(new Error('Invalid userId: must be a number between 0 and 999999'), null);
        }

        usersCol.findOne({
            _id: parsedId
        }, callback);
    };

    this.getUserByUserName = (userName, callback) => {
        // Fix for A1 - NoSQL Injection: Validate input type AND content
        // Prevent query operator injection (e.g., {"$ne": null})
        if (typeof userName !== 'string') {
            return callback(new Error('Invalid userName: must be a string'), null);
        }
        
        // Validate userName format: alphanumeric, underscore, dash (max 50 chars)
        const userNamePattern = /^[a-zA-Z0-9_-]{1,50}$/;
        if (!userNamePattern.test(userName)) {
            return callback(new Error('Invalid userName format: only alphanumeric, underscore, and dash allowed'), null);
        }

        usersCol.findOne({
            userName: userName
        }, callback);
    };

    this.getNextSequence = (name, callback) => {
        db.collection("counters").findAndModify({
                _id: name
            }, [], {
                $inc: {
                    seq: 1
                }
            }, {
                new: true
            },
            (err, data) =>  err ? callback(err, null) : callback(null, data.value.seq));
    };
}

module.exports = { UserDAO };
