const express = require("express")
const cors = require('cors')
const multer = require("multer")
const jwt = require('jsonwebtoken')
const cookieParser = require("cookie-parser")
const db_access = require("./db")
const db = db_access.db
const bcrypt = require('bcrypt')
const server = express()
const port = 3001
const secret_key = 'verySecretkey'

server.use("/uploads", express.static("uploads"))

server.use(cors({ 
    origin: "http://localhost:3002", 
    credentials: true 
    }))
server.use(express.json())
server.use(cookieParser())

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, "uploads/") 
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + "-" + file.originalname) 
    },
  })
  const upload = multer({ storage })

const generateToken= (id, isAdmin) =>{
    return jwt.sign({id,isAdmin}, secret_key, {expiresIn: '1h'})
}

const verifyToken = (req, res, next) => {
    const token = req.cookies.authToken || req.headers.authorization?.split(" ")[1]
    if (!token) 
      return res.status(401).send("Unauthorized")
    jwt.verify(token, secret_key, (err, details) => {
      if (err)
        return res.status(403).send("Invalid or expired token")
      req.userDetails = details
      next()
    })
  }

// User Registration
server.post("/user/register", async (req, res) => {
    const { name, idnumber, email, password } = req.body

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).send('error hashing password')
        }
        db.run(`INSERT INTO USER(NAME, IDNUMBER, EMAIL, PASSWORD, ISADMIN) VALUES(?, ?, ?, ?, ?)`,
         [name, idnumber, email, hashedPassword, 0], 
         (err) => {
            if (err) {

                return res.status(401).send(err)
            }
            else
                return res.status(200).send(`registration successfull`)
        })
    })
})

//Any User or Admin same Login Route
server.post("/login", async (req, res) => {
    const { email, password } = req.body

    const ADMIN_EMAIL = "admin@auction.com"
    const ADMIN_PASSWORD = "NoorsAuction"
    if (email === ADMIN_EMAIL) {
        if (password === ADMIN_PASSWORD) {
            const token = generateToken(1, true) // Generate admin token
            console.log("Generated Token (Admin):", token) // Debug log
            return res.status(200).json({ token, admin: true })
        } else {
            return res.status(401).json({ message: "Invalid admin credentials" })
        }
    }
    // User Login
    db.get("SELECT * FROM USER WHERE EMAIL = ?", [email], async (err, row) => {
        if (err || !row) {
            return res.status(401).json({ message: "Invalid user credentials" })
        }

        const passwordMatch = await bcrypt.compare(password, row.PASSWORD)
        if (!passwordMatch) {
            return res.status(401).json({ message: "Invalid user credentials" })
        }

        const token = generateToken(row.ID, row.ISADMIN) // Generate user token
        console.log("Generated Token (User):", token) // Debug log
        return res.status(200).json({ token, admin: row.ISADMIN === 1 })
    })
})

//Admin Users list
server.get("/admin/view_users", verifyToken, (req, res) => {
    const isAdmin = req.userDetails.isAdmin 
    if (!isAdmin) {
      console.log("Access denied: User is not an admin")
      return res.status(403).send("You are not an admin")
    }
    db.all("SELECT ID, NAME, EMAIL, IDNUMBER FROM USER", (err, rows) => {
      if (err) {
        console.error("Error retrieving users:", err.message)
        return res.status(500).send("Error retrieving users")
      }
      console.log("Users retrieved successfully:", rows)
      res.status(200).json(rows)
    })
  })  

  //Admin List Creation
server.post("/admin/create_listing", upload.single("image"), verifyToken, (req, res) => {
  const { category, name, brand, style, size, color, hardware, material, startingBid, duration } = req.body
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null
  if (!imageUrl) {
    return res.status(400).send("Image is required.")
  }
  const endAt = new Date()
  endAt.setDate(endAt.getDate() + parseInt(duration))
  db.run(
    `INSERT INTO LISTING (CATEGORY, IMAGE_URL, NAME, BRAND, STYLE, SIZE, COLOR, HARDWARE, MATERIAL, STARTING_BID, CURRENT_BID, DURATION, END_AT)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [category, imageUrl, name, brand, style, size, color, hardware, material, parseFloat(startingBid), parseFloat(startingBid), parseInt(duration), endAt.toISOString()],
  (err) => {
    if (err) {
      console.error("Error saving listing to database:", err.message)
    return res.status(500).send("Error saving listing to database.")
    }
    console.log("New Listing Saved to Database:", { name, category })
    res.status(200).json({ message: "Listing created successfully!" })
    })
})
  
//Admin Accessing All Listings
server.get("/admin/all_listings", verifyToken, (req, res) => {
  const isAdmin = req.userDetails.isAdmin
  if (!isAdmin) {
    return res.status(403).send("You are not an admin")
  }
  db.all("SELECT * FROM LISTING", (err, rows) => {
    if (err) {
      console.error("Error retrieving listings:", err.message)
    return res.status(500).send("Error retrieving listings")
    }
    res.status(200).json(rows)
  })
})

//Handbags Listings
server.get("/listings/handbags", (req, res) => {
  db.all("SELECT * FROM LISTING WHERE CATEGORY = 'Handbags'", 
  (err, rows) => {
    if (err) {
      console.error("Error retrieving handbags:", err.message)
    return res.status(500).send("Error retrieving handbags")
    }
    res.status(200).json(rows)
  })
})

//Watches Listings
server.get("/listings/watches", (req, res) => {
  db.all("SELECT * FROM LISTING WHERE CATEGORY = 'Watches'", 
  (err, rows) => {
    if (err) {
      console.error("Error retrieving watches:", err.message)
    return res.status(500).send("Error retrieving watches")
    }
    res.status(200).json(rows)
  })
})

//Specific Listing
server.get("/listing/:id", (req, res) => {
  const listingId = req.params.id

  db.get(
    "SELECT * FROM LISTING WHERE ID = ?",
    [listingId],
    (err, row) => {
      if (err) {
        console.error("Error fetching listing details:", err.message)
        return res.status(500).send("Error retrieving listing details.")
      }
      if (!row) {
        return res.status(404).send("Listing not found.")
      }
      res.status(200).json(row)
    }
  )
})  

//Admin Editing
server.put('/admin/edit_listing/:id/:startingbid', verifyToken, (req, res) => {
  const isAdmin = req.userDetails.isAdmin
  if(isAdmin!== 1)
    return res.status(403).send("you are not an admin")
    const query = `UPDATE LISTING SET STARTING_BID=${parseInt(req.params.startingbid, 10)}
      WHERE ID=${req.params.id}`
      db.run(query, (err) => {
        if (err) {
          console.log(err)
          return res.send(err)
        }
        else {
          return res.send(`Listing updated successfully`)
          }
    })
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

// Place a Bid (User)
server.post("/bid", verifyToken, (req, res) => {
    const {listingId, bidAmount} = req.body
    const userId = req.userDetails.id

    console.log("Received listingId:", listingId)
    db.get(
        "SELECT * FROM LISTING WHERE ID = ?",
        [listingId],
        (err, listing) => {
            if (err) return res.status(500).send("Error fetching listing.")
            if (!listing) return res.status(404).send("Listing not found.")

            const currentTime = new Date().toISOString()
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
                        return res.status(500).send("Error updating current bid.")
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
    const listingId = req.params.id

    db.get(
        "SELECT CURRENT_BID FROM LISTING WHERE ID = ?",
        [listingId],
        (err, listing) => {
            if (err) {
                console.error("Error fetching current bid:", err.message)
                return res.status(500).send("Error fetching current bid.")
            }
            if (!listing) {
                return res.status(404).send("Listing not found.")
            }
            res.status(200).json({ currentBid: listing.CURRENT_BID })
        }
    )
})

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
    console.log(`Server running on port ${port}`)
    db.serialize(() => {
        db.exec(db_access.createUSERtable, (err) => {
            if (err) console.error("Error creating USER table:", err.message)
            else console.log("USER table ready.")
        })
        db.exec(db_access.createLISTINGtable, (err) => {
            if (err) console.error("Error creating LISTING table:", err.message)
            else console.log("LISTING table ready.")
        })
        db.exec(db_access.createBIDDINGtable, (err) => {
            if (err) console.error("Error creating BIDDING table:", err.message)
            else console.log("BIDDING table ready.")
        })
    })
})


module.exports = server
