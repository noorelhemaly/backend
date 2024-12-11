const express = require("express")
const cors = require('cors')
const jwt = require('jsonwebtoken')
const cookieParser = require("cookie-parser")
const db_access = require("./db")
const db = db_access.db
const bcrypt = require('bcryptjs');
const server = express()
const port = 500
const secert_key = 'qwertasdfzxcv'

server.use(cors({ origin: "http://localhost:3000", credentials: true }));
server.use(express.json())
server.use(cookieParser())

const generateToken= (id, isAdmin) =>{
    return jwt.sign({id,isAdmin}, secert_key, {expiresIn: '1h'})
}

const verifyToken= (req, res, next) =>{
    const token = req.cookies.authToken
    if(!token)
        return res.status(401).send("unauthorized")

    jwt.verify(token,secert_key,(err,details) =>{
        if(err)
            return res.status(403).send("invalid or expired token")
        req.userDetails=details

        next()
    })
}

const verifyUser = (req, res, next) => {
    const token = req.cookies.authToken
    if (!token) 
        return res.status(401).send("Unauthorized")

    jwt.verify(token, secert_key, (err, details) => {
        if (err) 
            return res.status(403).send("Invalid or expired token")
        req.userDetails = details

        next()
    })
}

// User Registration
server.post("/user/register", async (req, res) => {
    const { name, idnumber, email, password } = req.body
    const isAdmin = 0

    try {
        const hashedPassword = await bcrypt.hash(password, 10)

    db.run(
        "INSERT INTO USER(NAME, IDNUMBER, EMAIL, PASSWORD, ISADMIN) VALUES(?, ?, ?, ?, ?)",
        [name, parseInt(idnumber), email, hashedPassword, isAdmin],
        (err) => {
            if (err) {
                if (err.code === "SQLITE_CONSTRAINT") {
                    return res.status(400).send("IDNUMBER or EMAIL already exists")
                }
                return res.status(500).send("Database Error")
            }
            res.status(200).send("Registration successful, account created.")
        })
    }catch (error) {
        console.error("Error hashing password:", error.message);
        res.status(500).send("Internal server error");
    }
})

// Admin Login
server.post("/admin/login", (req, res) => {
    const { email, password } = req.body

    if (email === "admin@auction.com" && password === "NoorsAuction") {
        res.cookie("adminToken", "secure_admin_session_token", { httpOnly: true })
        return res.status(200).send("Admin login successful")
    } else {
        return res.status(401).send("Invalid admin credentials")
    }
})

// User Login
server.post("/user/login", (req, res) => {
    const { email, password } = req.body

    db.get(
        "SELECT * FROM USER WHERE EMAIL = ?",
        [email],
        async (err, row) => {
            if(err || !row){
                return res.status(401).send("Invalid credentials")
            }

            const passwordMatch = await bcrypt.compare(password, row.PASSWORD)
            if (!passwordMatch) {
                return res.status(401).send("Invalid credentials")
            }

            const token = generateToken(row.ID, row.ISADMIN)
            res.cookie('authToken', token,{
                httpOnly:true,
                sameSite:'strict',
                expiresIn: '1h'
            })
            res.status(200).send("login successful")
        })
})

//View Users (Admin)
server.get("/admin/view_users", verifyToken, (req, res) => {
    const isAdmin = req.userDetails.isAdmin
    if(isAdmin!== 1)
        return res.status(403).send("you are not an admin")

    db.all("SELECT ID, NAME, EMAIL FROM USER", (err, rows) => {
        if (err) {
            return res.status(500).send("Error retrieving users")
        }
        res.status(200).json(rows)
    })
})

server.post('/admin/create_listing', verifyToken, (req, res) => {
    console.log(`user details: ${JSON.stringify(req.userDetails)}`)
    const isAdmin = req.userDetails.isAdmin
    if(isAdmin!== 1)
        return res.status(403).send("you are not an admin")

    const {category, imageUrl,name,brand,style,size,color,hardware,material,startingBid,duration} = req.body
    const endAt = new Date()
    endAt.setDate(endAt.getDate() + parseInt(duration))

    db.run(
        `INSERT INTO LISTING (CATEGORY, IMAGE_URL, NAME, BRAND, STYLE, SIZE, COLOR, HARDWARE, MATERIAL, STARTING_BID, CURRENT_BID, DURATION, END_AT)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [category, imageUrl, name, brand, style, size, color, hardware, material, startingBid, startingBid, duration, endAt.toISOString()],
        (err) => { 
            if (err) {
                console.error("Error creating listing:", err.message)
                return res.status(500).send("Error creating listing.")
            }
            res.status(200).send(`Listing created for ${category} ending on ${endAt.toISOString()}.`)
        })
})


server.put('/admin/edit_listing/:id', verifyToken, (req, res) => {
    const isAdmin = req.userDetails.isAdmin
    if(isAdmin!== 1)
        return res.status(403).send("you are not an admin")

    const listingId = req.params.id
    const {category,imageUrl,name,brand,style,size,color,hardware,material,startingBid,duration} = req.body

    const endAt = new Date()
    endAt.setDate(endAt.getDate() + parseInt(duration))

    db.run(
        `UPDATE LISTING 
        SET CATEGORY = ?, IMAGE_URL = ?, NAME = ?, BRAND = ?, STYLE = ?, SIZE = ?, COLOR = ?, HARDWARE = ?, MATERIAL = ?, STARTING_BID = ?, CURRENT_BID = ?, DURATION = ?, END_AT = ?
        WHERE ID = ?`,
        [category,imageUrl,name,brand,style,size,color,hardware,material,startingBid,startingBid,duration,endAt.toISOString(),listingId],
        
        (err) => {
            if (err) {
                console.error("Error editing listing:", err.message)
                return res.status(500).send("Error editing listing.")
            }
            res.status(200).send("Listing updated successfully.")
        })
})


//Get All Listings (Admin)
server.get("/admin/all_listings", verifyToken, (req, res) => {
    const isAdmin = req.userDetails.isAdmin
    if(isAdmin!== 1)
        return res.status(403).send("you are not an admin")

    db.all("SELECT * FROM LISTING", (err, rows) => {
        if (err) {
            console.error("Error retrieving listings:", err.message)
            return res.status(500).send("Error retrieving listings")
        }
        res.status(200).json(rows)
    })
})

server.get("/listings/handbags", (req, res) => {
    db.all(`SELECT * FROM LISTING WHERE CATEGORY = 'Handbags'`, (err, rows) => {
        if (err) {
            return res.status(500).send("Error retrieving handbags")
        }
        res.status(200).json(rows)
    })
})

// Fetch Only Watches Listings
server.get("/listings/watches", (req, res) => {
    db.all(`SELECT * FROM LISTING WHERE CATEGORY = 'Watches'`, (err, rows) => {
        if (err) {
            return res.status(500).send("Error retrieving watches")
        }
        res.status(200).json(rows)
    })
})

//Get active listing
server.get('/listings', (req, res) => {
    const currentTime = new Date().toISOString()

    db.all(
        `SELECT * FROM LISTING WHERE END_AT > ?`, // Only fetch active listings
        [currentTime],
        (err, rows) => {
            if (err) {
                console.error("Error retrieving listings:", err.message)
                return res.status(500).json({ error: "Error retrieving listings." })
            }
            res.status(200).json(rows)
        }
    )
})

//Delete Listing (Admin)
server.delete("/admin/delete_listing/:id", verifyToken, (req, res) => {
    const isAdmin = req.userDetails.isAdmin
    if(isAdmin!== 1)
        return res.status(403).send("you are not an admin")

    const listingId = req.params.id

    db.run("DELETE FROM LISTING WHERE ID = ?", [listingId], (err) => {
        if (err) {
            return res.status(500).send("Error deleting listing")
        }
        res.status(200).send("Listing deleted successfully")
    })
})

// Place a Bid (User)
server.post("/bid", verifyUser, (req, res) => {

    const {listingId, bidAmount} = req.body
    const userId = req.userDetails.id

    console.log("Received listingId:", listingId)
    db.get(
        "SELECT * FROM LISTING WHERE ID = ?",
        [listingId],
        (err, listing) => {
            if (err) return res.status(500).send("Error fetching listing.")
            if (!listing) return res.status(404).send("Listing not found.")

            const currentTime = new Date().toISOString();
            if (currentTime > listing.END_AT) {
                return res.status(400).send("This listing has expired.")
            }
            if (bidAmount <= listing.CURRENT_BID) {
                return res.status(400).send(`Your bid must be higher than the current bid of ${listing.CURRENT_BID}.`)
            }

            db.run(
                "UPDATE LISTING SET CURRENT_BID = ? WHERE ID = ?",
                [bidAmount, listingId],
                (err) => {
                    if (err) {
                        return res.status(500).send("Error updating current bid.");
                    }

                    db.run(
                        "INSERT INTO BIDDING (USER_ID, LISTING_ID, BID_AMOUNT) VALUES (?, ?, ?)",
                        [userId, listingId, bidAmount],
                        (err) => {
                            if (err) {
                                return res.status(500).send("Error placing bid")
                            }
                            res.status(200).send("Bid placed successfully")
                        })
                })
        })
})

server.get('/listing/:id/current_bid', (req, res) => {
    const listingId = req.params.id;

    db.get(
        "SELECT CURRENT_BID FROM LISTING WHERE ID = ?",
        [listingId],
        (err, listing) => {
            if (err) {
                console.error("Error fetching current bid:", err.message);
                return res.status(500).send("Error fetching current bid.");
            }
            if (!listing) {
                return res.status(404).send("Listing not found.");
            }
            res.status(200).json({ currentBid: listing.CURRENT_BID });
        }
    );
});

const checkExpiredListings = () => {
    const currentTime = new Date().toISOString()

    db.run(
        `UPDATE LISTING SET STATUS = 'EXPIRED' WHERE END_AT <= ?`, 
        [currentTime], 
        (err) => {
            if (err) {
                console.error("Error updating expired listings:", err.message)
            } else {
                console.log("Expired listings updated successfully.")
            }
        })
}

setInterval(checkExpiredListings, 60000)


server.listen(port, () => {
    console.log(`Server running on port ${port}`);
    db.serialize(() => {
        db.exec(db_access.createUSERtable, (err) => {
            if (err) console.error("Error creating USER table:", err.message);
            else console.log("USER table ready.");
        });
        db.exec(db_access.createLISTINGtable, (err) => {
            if (err) console.error("Error creating LISTING table:", err.message);
            else console.log("LISTING table ready.");
        });
        db.exec(db_access.createBIDDINGtable, (err) => {
            if (err) console.error("Error creating BIDDING table:", err.message);
            else console.log("BIDDING table ready.");
        });
    });
});


module.exports = server
