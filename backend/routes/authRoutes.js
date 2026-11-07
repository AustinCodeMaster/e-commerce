const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("../db");
const { randomInt } = require("node:crypto");
const transporter = require("../mailer");
const router = express.Router();


router.post("/register", async (req, res) => {
    const body = req.body ?? {};

    const first_name = typeof body.first_name === "string" ? body.first_name.trim() : "";
    const last_name = typeof body.last_name === "string" ? body.last_name.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = body.password;


    // Validate the signup details before querying the database.
    if (!first_name || !last_name) {
        return res.status(400).json({
            message: "First and last name are required"
        });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
            message: "Enter a valid email address"
        });
    }

    if (typeof password !== "string" || password.length < 8) {
        return res.status(400).json({
            message: "Use at least 8 characters for your password"
        });
    }

    if (Buffer.byteLength(password, "utf8") > 72) {
        return res.status(400).json({
            message: "Password exceeds the 72-byte limit"
        });
    }

    try {
        const existingUsers = await pool.query(
            "SELECT user_id FROM users WHERE email = ?",
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({
                message: "Email is already registered"
            });
        }
        
        const verificationCode = randomInt(100000, 1000000).toString();
        const verificationCodeHash = await bcrypt.hash(verificationCode, 10);
        const verificationCodeExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

        const passwordHash = await bcrypt.hash(password, 10);

        await pool.query(
            `INSERT INTO users
                (first_name, last_name, email, password_hash, role, email_verified, verification_code_hash, verification_code_expires_at, verification_code_sent_at)
             VALUES (?, ?, ?, ?, 'customer', FALSE, ?, ?, NOW())`,
            [first_name, last_name, email, passwordHash, verificationCodeHash, verificationCodeExpiresAt]
        );
        
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify your Bag Shop account",
            text: `Your verification code is ${verificationCode}. It expires in 10 minutes.` 
        });

        return res.status(201).json({
            message: "Account created. Check your email for your verification code."
        });
    } catch (error) {
        // Two simultaneous requests can both pass the email check.
        // The UNIQUE constraint on email prevents the second insert.
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
                message: "Email is already registered"
            });
        }

        console.error("Registration failed:", error.code);
        return res.status(500).json({
            message: "Something went wrong"
        });
    }
});

router.post("/verify-email", async (req, res) => {
   //Read the submited data.
   //yse an empty object if the request body is missing.
   const body = req.body ?? {};

   //Remove surrounding spaces and convert the email to lowercase.
   //If the email is not a string, use an empty string.
   const email = typeof body.email === "string"
       ?body.email.trim().toLowerCase()
       : "";

    //The customer must submit the code as a string.
    const code = typeof body.code === "string"
    ? body.code.trim()
    : "";

    //Require an email and a code containing exactly six digits.
    if(!email || !/^\d{6}$/.test(code)) {
        return res.status(400).json({
            message: "Email and a six-digit verifcation code are required"
        });
    }

    try {
        // Find the account belonging to the submitted email.
        // The  ? receives the email value from the array.
        const users = await pool.query(
            `SELECT user_id, email_verified, verification_code_hash, verification_code_expires_at
             FROM users
             WHERE email = ?`,
            [email]
        );

        //Query results are an array. Take the first mathcing account.
        const user = users[0];

        //Stop if there is no account with this email.
        if(!user) {
            return res.status(400).json({
                message:"Invalid verification details"
            });
        }

        //stop if account has already been verified.
        if (user.email_verified) {
            return res.status(400).json({
                message: "Email is already verified"
            });
        }

        //Reject  codes that are missing or have expired.
        //getTime() and Date.now() both give the time in milliseconds
        if (
            !user.verification_code_hash ||
            !user.verification_code_expires_at ||
            new Date(user.verification_code_expires_at).getTime() <= Date.now()
        ) {
            return res.status(400).json({
                message: "Verification code has expired or is unavaliable"
            });
        }
        //count rhis attempt BEFORE checking whether the code matches.
        //The database only allows the update if:
        // - the account is still  unverified,
        // - fewer than five attemps have been used,
        // - the stored code has not changed,
        // - the code has not expired
        //
        // Combinig the check increment in one UPDATE prevents
        //simultaneos requests from bypassing the five attempt limit.
       const attempt = await pool.query(
            `UPDATE users
             SET verification_attempts = verification_attempts + 1
             WHERE user_id = ?
               AND email_verified = FALSE
               AND verification_attempts < 5
               AND verification_code_hash = ?
               AND verification_code_expires_at > NOW()`,
            [user.user_id, user.verification_code_hash]
        );

        // Zero affected rows means the conditions above were not met.
        if (attempt.affectedRows === 0) {
            return res.status(400).json({
                message: "Verification unavailable. The code may have expired or reached its attempt limit."
            });
        }

        // Compare the submitted code with the stored hash.
        // bcrypt returns true or false; it does not decrypt the hash.
        const isCodeValid = await bcrypt.compare(
            code,
            user.verification_code_hash
        );

        // Stop if the submitted code is incorrect.
        // This attempt has already been counted.
        if (!isCodeValid) {
            return res.status(400).json({
                message: "Invalid verification code"
            });
        }

        // Mark the email as verified and remove the used code.
        // Recheck the code and expiry in case they changed while
        // bcrypt was comparing the submitted code.
        const result = await pool.query(
            `UPDATE users
             SET email_verified = TRUE,
                 verification_code_hash = NULL,
                 verification_code_expires_at = NULL
             WHERE user_id = ?
               AND email_verified = FALSE
               AND verification_code_hash = ?
               AND verification_code_expires_at > NOW()`,
            [user.user_id, user.verification_code_hash]
        );

        // Only report success if the account was actually updated.
        if (result.affectedRows === 0) {
            return res.status(400).json({
                message: "Verification code is no longer valid"
            });
        }

        return res.status(200).json({
            message: "Email verified successfully"
        });
    } catch (error) {
        // Log the error code in the server terminal.
        console.error("Email verification failed:", error.code);

        // Send a general error message to the customer.
        return res.status(500).json({
            message: "Something went wrong"
        });
    }
});

router.post("/resend-verification", async (req, res) => {
   //read the request body safely.
   const body = req.body ?? {};

   //Remove surrounding spaces and convert the email  to lowecase.
   const email = typeof body.email === "string"
       ? body.email.trim().toLowerCase()
       : "";
    
    // Require an email with a valid basic format
     if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
            message: "Enter a valid email address"
        });
    }

    try {
        //Find the account and check whether another code can be sent.
        const users = await pool.query(
           `SELECT user_id, email_verified,
                (verification_code_sent_at IS NULL
                 OR verification_code_sent_at <= NOW() - INTERVAL 60 SECOND)
                AS can_resend
                FROM users
                WHERE email = ?`,
                [email]  
        );

        const user = users[0];

        //Use the same response for missing and already-verified accounts.
        //This avoids revealing whether an email belongs to an account.
        if (!user || user.email_verified) {
            return res.status(200).json({
                message: "If this account needs verification, a code will be sent."
            });
        }

        // Stop if fewer than 60 seconds have passed.
        if (!user.can_resend) {
            return res.status(429).json({
                message: "Please wait 60 seconds between verification code requests."
            });
        }

        //Generate a new six-digit code and hash it
        const verificationCode = randomInt(100000, 1000000).toString();
        const verificationCodeHash = await bcrypt.hash(verificationCode, 10);

        //Replace the old code, give it 10 minutes, and reset attempts.
        //Check the column again here to prevent simultaenous resends
        const result = await pool.query(
            `UPDATE users
     SET verification_code_hash = ?,
         verification_code_expires_at = NOW() + INTERVAL 10 MINUTE,
         verification_attempts = 0,
         verification_code_sent_at = NOW()
     WHERE user_id = ?
       AND email_verified = FALSE
       AND (
           verification_code_sent_at IS NULL
           OR verification_code_sent_at <= NOW() - INTERVAL 60 SECOND
       )`,
        [verificationCodeHash, user.user_id]
        );
        
        //Only send an Email of this request updated the account.
        if (result.affectedRows === 0) {
                return res.status(429).json({
                   message: "A new code cannot be sent right now. Please wait before trying again."
            });
           }
        
        // Send the actual code to the customer's email.
        //Only its hash is stored in the database.
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your new Bag Shop verification code",
            text: `Your verificaton code is ${verificationCode}. It expires in 10 minutes.`
        });
        
        return res.status(200).json({
            message: "If this account needs verification, a code will be sent."
        });
        
    } catch (error) {
        console.error("Resending verification failed:", error.code);

        return res.status(500).json({
            message: "something went wrong"
        });
    }
});

module.exports = router;