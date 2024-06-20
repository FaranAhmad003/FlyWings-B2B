const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const speakeasy = require("speakeasy");
const session = require("express-session");
const { exec } = require("child_process");
const app = express();
const port = 3000;
const { setUsername, getUsername } = require("./userdata");
const { setUserId, getUserId } = require("./userdata");
const fs = require("fs");
const server = require("http").Server(app);
const io = require("socket.io")(server);
const path = require("path");
const nodemailer = require("nodemailer");
require("html");
// Middleware to parse JSON in the request body
app.use(bodyParser.json());

app.use(express.static(__dirname));
const crypto = require("crypto");
const secret = crypto.randomBytes(64).toString("hex");
const adminsecret=crypto.randomBytes(64).toString("hex");
console.log(secret);
app.use(
  session({
    secret: secret, // Change this to a secure secret key
    resave: false,
    saveUninitialized: true,
  })
);
app.use(
  session({
    secret: adminsecret, // Change this to a secure secret key
    resave: false,
    saveUninitialized: true,
  })
);
// MySQL connection
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "12345678",
  database: "Flywings",
});
const transporter = nodemailer.createTransport({
  service: "Gmail", // Use your email service
  auth: {
    user: "chatbotx092@gmail.com", // Your email
    pass: "vlep zify kiem sntq", // Your email password
  },
});
// Connect to MySQL
connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
  } else {
    console.log("Connected to MySQL database");
  }
});

//middleware--------------
function requireLogin(req, res, next) {
  console.log(req.session);
  if (req.session && req.session.userId) {
    next();
  } else {
    res.redirect("/"); // Redirect to login page if not logged in
  }
}
function requireAdmin(req, res, next) {
  if (
    req.session &&
    req.session.userInfo &&
    req.session.userInfo.user_type === "admin"
  ) {
    next();
  } else {
    res.redirect("/");
  }
}

function requireClient(req, res, next) {
  if (
    req.session &&
    req.session.userInfo &&
    req.session.userInfo.user_type === "client"
  ) {
    next();
  } else {
    res.redirect("/");
  }
}


// Serve the HTML page
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});
//logout
// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).send('Failed to log out.');
    }
    res.redirect('/'); // Redirect to login page after logout
  });
});

app.get("/signup", (req, res) => {
  res.sendFile(__dirname + "/public/signup.html");
});
app.get("/admin/ledger", requireAdmin, (req, res) => {
  res.sendFile(__dirname + "/public/ledger.html");
});

// Route to print the entire 'user' table
app.get("/printTable", (req, res) => {
  connection.query("SELECT * FROM user", (err, results) => {
    if (err) {
      console.error("Error fetching data from user table:", err);
      res.status(500).json({ error: "Internal Server Error" });
    } else {
      console.log("User table data:", results);
      res.json(results);
    }
  });
});
app.get("/signupSuccess", (req, res) => {
  res.sendFile(__dirname + "/public/signupSuccess.html");
});
app.get("/client/Ledger", requireLogin, (req, res) => {
  res.sendFile(__dirname + "/public/clientLedger.html");
});
// Handle signup POST request
app.post("/signup", (req, res) => {
  const formData = req.body;

  // Check if the email ends with '@gmail.com'
  if (!formData.email.endsWith("@gmail.com")) {
    return res.status(400).json({
      error: "Invalid email address. Only Gmail addresses are allowed.",
    });
  }
  if (!isPasswordComplex(formData.password)) {
    return res.status(400).json({
      error:
        "Password must contain at least one capital letter, one numeric character, and one special character.",
    });
  }
  const secretKey = speakeasy.generateSecret({ length: 20 }).base32;
  connection.query(
    "INSERT INTO user (first_name, last_name, username, password, email, phone_no, secret_key,user_type) VALUES (?, ?, ?, ?, ?, ?, ?,?)",
    [
      formData.firstName,
      formData.lastName,
      formData.username,
      formData.password,
      formData.email,
      formData.phoneNo,
      secretKey,
      "client",
    ],
    (err, results) => {
      if (err) {
        console.error("Error inserting data into user table:", err);
        res.status(500).json({ error: "Internal Server Error" });
      } else {
        console.log("Inserted data into user table:", results);
        // Send both success message and secret key in the response
        res.json({ message: "Signup successful!", secretKey: secretKey });
      }
    }
  );
});
app.get("/usernames", (req, res) => {
  connection.query(
    'SELECT username FROM user where user_type = "client"',
    (err, results) => {
      if (err) {
        console.error("Error fetching usernames:", err);
        res.status(500).json({ error: "Internal Server Error" });
      } else {
        // Extract usernames from the results
        const usernames = results.map((row) => row.username);
        res.json(usernames);
      }
    }
  );
});
app.get("/client/myBooking", requireLogin, (req, res) => {
  const userId = req.query.userId; // Get the userId from query parameters
  console.log("User ID for myBooking:", userId);
  // You can now use userId for further processing, such as fetching user-specific bookings

  const filePath = path.join(__dirname, "public", "myBooking.html");
  fs.readFile(filePath, "utf8", (err, html) => {
    if (err) {
      res.status(500).send("Failed to load the myBooking page.");
      return;
    }
    // Customize the HTML response if needed
    const customizedHtml = html.replace("{{userId}}", userId);
    res.send(customizedHtml);
  });
});

app.get("/tickets", (req, res) => {
  const username = getUsername();
  console.log("Username:", username);
  const group = req.query.group;
  let query; // Declare query variable outside the if-else statements
  if (group === "uae") {
    query =
      'SELECT *, to_location AS toLocation, from_location AS fromLocation FROM tickets WHERE to_location IN ("Dubai", "Abu Dhabi", "Sharjah", "Ras al-Khaimah", "Muscat") AND no_of_tickets > 0 AND ticket_status = "active";';
  } else if (group === "ksa") {
    query =
      'SELECT *, to_location AS toLocation, from_location AS fromLocation FROM tickets WHERE to_location IN ("Muscat", "Salalah", "Sohar", "Duqm", "Khasab", "Musandam", "Nizwa", "Sur", "Masirah", "Buraimi", "Ibri", "Rustaq", "Thumrait", "Marmul", "Fahud", "Qarn Alam", "Mukhaizna", "Jaaluni", "Adam") AND no_of_tickets > 0 AND ticket_status = "active";';
  } else if (group === "umrah") {
    query =
      'SELECT *, to_location AS toLocation, from_location AS fromLocation FROM tickets WHERE to_location IN ("Riyadh", "Jeddah", "Dammam", "Medina", "Abha", "Tabuk", "Taif", "Qassim", "Yanbu", "Hail") AND no_of_tickets > 0 AND ticket_status = "active";';
  } else if (group === "all") {
    query =
      'SELECT *, to_location AS toLocation, from_location AS fromLocation FROM tickets WHERE ticket_status = "active";';
  } else {
    return res.status(400).json({ error: "Invalid group" });
  }
  connection.query(query, [username], (err, results) => {
    if (err) {
      console.error("Error fetching tickets:", err);
      res.status(500).json({ error: "Internal Server Error" });
    } else {
      //console.log("Tickets:", results);
      res.json(results);
    }
  });
});

app.get("/tickets/:id", function (req, res) {
  const id = req.params.id;
  const username = getUsername();
  const ticketQuery =
    "SELECT tickets.id AS ticket_id, tickets.* FROM tickets WHERE tickets.id = ?";
  const userQuery =
    "SELECT user.id as user_id, user.* FROM user WHERE user.username = ?";

  connection.query(ticketQuery, [id], (err, ticketResults) => {
    if (err) {
      res.status(500).json({ error: "Internal Server Error" });
    } else {
      connection.query(userQuery, [username], (err, userResults) => {
        if (err) {
          res.status(500).json({ error: "Internal Server Error" });
        } else {
          // use ticketResults and userResults
          const data = {
            ...ticketResults[0],
            ...userResults[0],
          };
          res.json(data);
        }
      });
    }
  });
});

function isPasswordComplex(password) {
  // Regular expressions to check for the required conditions
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumeric = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  // Check if all conditions are met
  return hasUpperCase && hasLowerCase && hasNumeric && hasSpecialChar;
}
app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});
app.get("/client",requireClient,(req, res) => {
  const userId = req.session.userId;
  const filePath = path.join(__dirname, "public", "client_home_page.html");
  fs.readFile(filePath, "utf8", (err, html) => {
    if (err) {
      res.status(500).send("Failed to load the client home page.");
      return;
    }
    const customizedHtml = html.replace("{{userId}}", userId);
    res.send(customizedHtml);
  });
});

app.get("/client/bank", requireLogin, (req, res) => {
  const filePath = path.join(__dirname, "public", "bankclient.html");
  fs.readFile(filePath, "utf8", (err, html) => {
    if (err) {
      res.status(500).send("Failed to load the bank page.");
      return;
    }
    res.send(html);
  });
});
app.get("/admin/bank",requireLogin, (req, res) => {
  const filePath = path.join(__dirname, "public", "bank.html");
  fs.readFile(filePath, "utf8", (err, html) => {
    if (err) {
      res.status(500).send("Failed to load the bank page.");
      return;
    }
    res.send(html);
  });
});

app.get("/admin",requireAdmin, (req, res) => {
  const filePath = path.join(__dirname, "public", "admin_home_page.html");
  fs.readFile(filePath, "utf8", (err, html) => {
    if (err) {
      res.status(500).send("Failed to load the client home page.");
      return;
    }
    res.send(html);
  });
});
app.get("/admin/ticketStatus", requireLogin, (req, res) => {
  const query = "SELECT * FROM tickets";
  connection.query(query, (err, tickets) => {
    if (err) {
      console.error("Failed to retrieve tickets:", err);
      res.status(500).send("Database query failed");
      return;
    }

    const filePath = path.join(__dirname, "public", "ticketStatus.html");
    fs.readFile(filePath, "utf8", (err, html) => {
      if (err) {
        console.error("Error reading the HTML file:", err);
        res.status(500).send("Failed to load the ticket status page.");
        return;
      }

      // Generate the rows of tickets dynamically
      let rows = tickets
        .map(
          (ticket) => `
        <tr>
          <td>${ticket.id}</td>
          <td>${ticket.date_of_ticket}</td>
          <td>${ticket.from_location}</td>
          <td>${ticket.to_location}</td>
          <td>${ticket.payment_status}</td>
          <td>
            <button onclick="updateTicket(${ticket.id}, 'APPROVED')">Approve</button>
            <button onclick="updateTicket(${ticket.id}, 'DISAPPROVED')">Disapprove</button>
          </td>
        </tr>`
        )
        .join("");

      // Insert rows into the HTML before sending it
      html = html.replace("<!-- Tickets will be added here -->", rows);
      res.send(html);
    });
  });
});

// Approve or disapprove tickets
app.post("/admin/ticketStatus/approve/:id/:status", (req, res) => {
  const { id, status } = req.params;
  const sql = "UPDATE tickets SET approval_status = ? WHERE id = ?";
  connection.query(sql, [status, id], (err, result) => {
    if (err) {
      console.error("Failed to update ticket status:", err);
      res.status(500).send("Failed to update ticket status");
      return;
    }
    res.send("Ticket status updated successfully");
  });
});
app.get("/forgotPassword", (req, res) => {
  res.sendFile(__dirname + "/public/forgotPasswordEmailEntry.html");
});
app.get("/otpVerification", (req, res) => {
  res.sendFile(__dirname + "/public/otpVerification.html");
});
app.get("/admin/allBooking", requireLogin, (req, res) => {
  const filePath = path.join(__dirname, "public", "allBooking.html");
  fs.readFile(filePath, "utf8", (err, html) => {
    if (err) {
      res.status(500).send("Failed to load the bank page.");
      return;
    }
    res.send(html);
  });
});
app.get("/admin/tickets", requireLogin, (req, res) => {
  const filePath = path.join(__dirname, "public", "Tickets.html");
  fs.readFile(filePath, "utf8", (err, html) => {
    if (err) {
      res.status(500).send("Failed to load the bank page.");
      return;
    }
    res.send(html);
  });
});
function savePassengers(passengers, callback) {
  // Start a transaction
  connection.beginTransaction((err) => {
    if (err) {
      callback(err);
      return;
    }

    // Loop over the passengers and insert each one into the database
    for (const passenger of passengers) {
      connection.query("INSERT INTO passengers SET ?", passenger, (err) => {
        if (err) {
          // If an error occurred, rollback the transaction
          connection.rollback(() => {
            callback(err);
          });
          return;
        }
      });
    }
    const query =
      "UPDATE tickets SET no_of_tickets = no_of_tickets - ? WHERE id = ?";
    connection.query(
      query,
      [passengers.length, passengers[0].ticket_id],
      (err, results) => {
        if (err) {
          // If an error occurred, rollback the transaction
          connection.rollback(() => {
            callback(err);
          });
          return;
        }
      }
    );
    // If no errors occurred, commit the transaction
    connection.commit((err) => {
      if (err) {
        // If an error occurred, rollback the transaction
        connection.rollback(() => {
          callback(err);
        });
        return;
      }

      callback(null);
    });
  });
}
app.get("/get_passenger", (req, res) => {
  const id = getUserId();
  connection.query(
    "SELECT passengers.id AS passenger_id, passengers.status AS passenger_status, tickets.id AS ticket_id, passengers.given_name AS given_name, passengers.surname AS last_name, passengers.*, tickets.* FROM passengers LEFT JOIN tickets ON passengers.ticket_id = tickets.id WHERE passengers.user_id = ? LIMIT 0, 1000;",
    [id],
    (err, results) => {
      if (err) {
        console.error("Error fetching passenger:", err);
        res.status(500).json({ error: "Internal Server Error" });
      } else {
        res.json(results);
      }
    }
  );
});
app.get("/get_approved_passengers", (req, res) => {
  const id = getUserId();
  connection.query(
    "SELECT passengers.id AS passenger_id, passengers.status AS passenger_status, tickets.id AS ticket_id, passengers.given_name AS given_name, passengers.surname AS last_name, passengers.*, tickets.* FROM passengers LEFT JOIN tickets ON passengers.ticket_id = tickets.id WHERE passengers.user_id = ? AND status = 'approved' LIMIT 0, 1000;",
    [id],
    (err, results) => {
      if (err) {
        console.error("Error fetching passenger:", err);
        res.status(500).json({ error: "Internal Server Error" });
      } else {
        res.json(results);
      }
    }
  );
});
app.get("/get_cancelled_passengers", (req, res) => {
  const id = getUserId();
  connection.query(
    "SELECT passengers.id AS passenger_id, passengers.status AS passenger_status, tickets.id AS ticket_id, passengers.given_name AS given_name, passengers.surname AS last_name, passengers.*, tickets.* FROM passengers LEFT JOIN tickets ON passengers.ticket_id = tickets.id WHERE passengers.user_id = ? AND status = 'rejected' OR status = 'cancelled' LIMIT 0, 1000;",
    [id],
    (err, results) => {
      if (err) {
        console.error("Error fetching passenger:", err);
        res.status(500).json({ error: "Internal Server Error" });
      } else {
        res.json(results);
      }
    }
  );
});
app.get("/get_all_passenger", (req, res) => {
  var username = getUsername();
  const status = req.query.status; // Retrieve status from query parameters

  let sqlQuery = `
       SELECT 
    passengers.id AS passenger_id,
    passengers.status AS passenger_status,
    tickets.id AS ticket_id,
    passengers.*,
    tickets.*,
    user.username AS clientname
FROM 
    passengers 
LEFT JOIN 
    tickets ON passengers.ticket_id = tickets.id 
LEFT JOIN 
    user ON passengers.user_id = user.id
    `;

  let params = [username]; // Start with username for the SQL parameters

  // Add SQL condition for status if it's provided and not for 'All'
  if (status && status !== "1") {
    sqlQuery += " WHERE passengers.status = 'approved'"; // Filter by status
    params.push(status);
    window.location.reload();
  }
  24;

  // Execute the query
  connection.query(sqlQuery, params, (err, results) => {
    if (err) {
      console.error("Error fetching passengers:", err);
      res.status(500).json({ error: "Internal Server Error" });
    } else {
      res.json(results);
    }
  });
});

app.post("/approve_passenger", (req, res) => {
  const passengerId = req.body.passengerId;

  connection.query(
    "UPDATE passengers SET status = ? WHERE id = ?",
    ["approved", passengerId],
    (err, results) => {
      if (err) {
        console.error("Error updating passenger status:", err);
        res.status(500).json({ error: "Internal Server Error" });
      } else {
        // Query to get the passenger's details
        const query = `
                    SELECT 
                        p.surname AS first_name, p.given_name AS last_name, p.status, u.email, 
                        t.from_location, t.to_location, t.deptTime 
                    FROM 
                        passengers p 
                    JOIN 
                        user u ON p.user_id = u.id 
                    JOIN 
                        tickets t ON p.ticket_id = t.id 
                    WHERE 
                        p.id = ? AND status = 'approved'
                `;

        connection.query(query, [passengerId], (err, result) => {
          if (err) {
            console.error("Error fetching passenger details:", err);
            res.status(500).json({ error: "Internal Server Error" });
          } else {
            const passenger = result[0];
            const email = passenger.email;

            // Email content
            const mailOptions = {
              from: "chatbotx092@gmail.com", // Your email
              to: email,
              subject: "Approval Notification",
              text: `Dear ${passenger.first_name} ${passenger.last_name},

Your status has been approved.

Details:
From: ${passenger.from_location}
To: ${passenger.to_location}
Departure Time: ${passenger.deptTime}

Thank you for choosing our service.

Best regards,
Your Company Name`,
            };

            // Send email
            transporter.sendMail(mailOptions, (err, info) => {
              if (err) {
                console.error("Error sending email:", err);
                res.status(500).json({ error: "Internal Server Error" });
              } else {
                console.log("Email sent: " + info.response);
                res.json({ success: true });
              }
            });
          }
        });
      }
    }
  );
});
app.post("/reject_passenger", (req, res) => {
  const passengerId = req.body.passengerId;

  // First, find the ticket_id associated with the passenger
  connection.query(
    "SELECT ticket_id FROM passengers WHERE id = ?",
    [passengerId],
    (err, results) => {
      if (err) {
        console.error("Error finding passenger ticket:", err);
        res.status(500).json({ error: "Internal Server Error" });
      } else if (results.length === 0) {
        res.status(404).json({ error: "Passenger not found" });
      } else {
        const ticketId = results[0].ticket_id;

        // Start a transaction
        connection.beginTransaction((err) => {
          if (err) {
            console.error("Error starting transaction:", err);
            res.status(500).json({ error: "Internal Server Error" });
          } else {
            // Update the passenger's status to 'rejected'
            connection.query(
              "UPDATE passengers SET status = ? WHERE id = ?",
              ["rejected", passengerId],
              (err, results) => {
                if (err) {
                  return connection.rollback(() => {
                    console.error("Error updating passenger status:", err);
                    res.status(500).json({ error: "Internal Server Error" });
                  });
                }

                // Increment the no_of_tickets in the tickets table
                connection.query(
                  "UPDATE tickets SET no_of_tickets = no_of_tickets + 1 WHERE id = ?",
                  [ticketId],
                  (err, results) => {
                    if (err) {
                      return connection.rollback(() => {
                        console.error("Error updating ticket count:", err);
                        res
                          .status(500)
                          .json({ error: "Internal Server Error" });
                      });
                    }

                    // Commit the transaction
                    connection.commit((err) => {
                      if (err) {
                        return connection.rollback(() => {
                          console.error("Error committing transaction:", err);
                          res
                            .status(500)
                            .json({ error: "Internal Server Error" });
                        });
                      }

                      res.json({ success: true });
                    });
                  }
                );
              }
            );
          }
        });
      }
    }
  );
});

app.post("/save_passenger", (req, res) => {
  const passengers = req.body.passengers;

  // Assuming you have a function to save passengers
  savePassengers(passengers, (err) => {
    if (err) {
      console.error("Error saving passengers:", err);
      res.status(500).json({ error: "Internal Server Error" });
    } else {
      res.json({ success: true });
    }
  });
});
app.post("/cancel_passengers", (req, res) => {
  const passengerIds = req.body.passengerIds;

  if (!Array.isArray(passengerIds)) {
    return res.status(400).json({ error: "passengerIds must be an array" });
  }

  const placeholders = passengerIds.map(() => "?").join(",");
  const query = `UPDATE passengers SET status = 'Cancelled' WHERE id IN (${placeholders})`;

  connection.query(query, passengerIds, (err, results) => {
    if (err) {
      console.error("Error cancelling passengers:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.json({ success: true });
  });
});
app.post("/forgotPassword", (req, res) => {
  const usernameOrEmail = req.body.usernameOrEmail;

  // Query the 'user' table to check if the username or email exists
  connection.query(
    "SELECT * FROM user WHERE username = ? OR email = ?",
    [usernameOrEmail, usernameOrEmail],
    (err, results) => {
      if (err) {
        console.error("Error checking username or email:", err);
        res.status(500).json({ error: "Internal Server Error" });
      } else {
        if (results.length > 0) {
          // User found
          const user = results[0];

          // Store the user's Google Authenticator secret key in the session (you may use a more secure storage mechanism)
          req.session.userSecretKey = user.secret_key;
          req.session.userId = user.id;

          // Generate a one-time password (OTP) using speakeasy and user's secret key
          const otp = speakeasy.totp({
            secret: user.secret_key,
            encoding: "base32",
          });

          // You can send the OTP to the user via email or other means

          // Send a success response back to the HTML page
          res.json({ success: true });
        } else {
          // User not found
          console.log("User not found");
          res.status(404).json({ error: "User not found" });
        }
      }
    }
  );
});
app.post("/verifyOTP", (req, res) => {
  const enteredOTP = req.body.enteredOTP;

  // Retrieve the user's Google Authenticator secret key from the session (you may use a more secure storage mechanism)
  const userSecretKey = req.session.userSecretKey;

  // Verify the entered OTP against the user's secret key
  const verificationResult = speakeasy.totp.verify({
    secret: userSecretKey,
    encoding: "base32",
    token: enteredOTP,
  });

  if (verificationResult) {
    // OTP is valid
    console.log("OTP verification successful!");
    res.json({ success: true });
    // You can redirect the user to a password reset page or perform other actions
  } else {
    // OTP is invalid
    console.log("Invalid OTP");
    res.status(401).json({ error: "Invalid OTP" });
  }
});
app.get("/setNewPassword", (req, res) => {
  res.sendFile(__dirname + "/setNewPassword.html");
});
app.post("/setNewPassword", (req, res) => {
  const newPassword = req.body.newPassword;

  // You need to identify the user for whom the password is being set
  // For example, you can use the user's session or another form of identification

  // For demonstration purposes, let's assume you have stored the user's ID in the session
  const userId = req.session.userId;

  if (userId) {
    // Update the user's password in the database
    connection.query(
      "UPDATE user SET password = ? WHERE id = ?",
      [newPassword, userId],
      (err, results) => {
        if (err) {
          console.error("Error updating password:", err);
          res.status(500).json({ error: "Internal Server Error" });
        } else {
          console.log("Password updated successfully");
          res.json({ success: true });
        }
      }
    );
  } else {
    // User not authenticated (session expired, etc.)
    console.log("User not authenticated");
    res.status(401).json({ error: "User not authenticated" });
  }
});
app.post("/login", (req, res) => {
  const formData = req.body;
  connection.query(
    "SELECT * FROM user WHERE username = ? AND password = ?",
    [formData.username, formData.password],
    (err, results) => {
      if (err) {
        console.error("Error checking login credentials:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      if (results.length > 0) {
        const user = results[0];
        console.log("User logged in successfully:", user);
        setUsername(formData.username);
        setUserId(user.id);
        name = formData.username;

        // Setting session data
        req.session.userInfo = {
          username: formData.username,
          user_type: user.user_type,
          userId: user.id,
        };
        req.session.userId = user.id; // Also set userId directly for easier access

        if (user.user_type === "admin") {
          console.log("Admin logged in successfully:", getUsername());
          return res.json({ success: true, userType: "admin" });
        } else if (user.user_type === "client") {
          console.log("Client logged in successfully:", getUsername());
          return res.json({
            success: true,
            userType: "client",
            userId: user.id,
          });
        } else {
          console.log("Invalid user_type");
          return res.status(401).json({ error: "Invalid user_type" });
        }
      } else {
        console.log("Invalid username or password");
        return res.status(401).json({ error: "Invalid username or password" });
      }
    }
  );
});


//=============admin side functionallity to handle here

io.on("connection", (socket) => {
  console.log("A user connected");

  // Fetch all tickets from the database
  connection.query("SELECT * FROM tickets", (err, results) => {
    if (err) {
      console.error("Error fetching tickets:", err);
      // Handle error (e.g., notify the client of the failure)
    } else {
      // Send all tickets to the newly connected client
      socket.emit("allTickets", results);
    }
  });
});

app.post("/createTicket", (req, res) => {
  // Your route handler logic here
  const {
    date_of_ticket,
    pnr,
    airline,
    time,
    arrivalTime,
    luggage_capacity,
    meal,
    fare,
    fromLocation,
    toLocation,
    bookedByUsername,
    flightNumber,
    paymentStatus,
    tripType,
    returnDate,
    returnTime,
  } = req.body;

  // Insert into tickets table
  connection.query(
    "INSERT INTO tickets (date_of_ticket, airline, deptTime, arrivalTime, luggage_capacity, meal, fare, from_location, to_location, no_of_tickets , flight_number, payment_status, trip_type, returnDate, returnTime, pnr) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      date_of_ticket,
      airline,
      time,
      arrivalTime,
      luggage_capacity,
      meal,
      fare,
      fromLocation,
      toLocation,
      bookedByUsername,
      flightNumber,
      paymentStatus,
      tripType,
      returnDate,
      returnTime,
      pnr,
    ],
    (err, results) => {
      if (err) {
        console.error("Error inserting ticket:", err); // Log the error
        return res
          .status(500)
          .json({ error: "Internal Server Error", details: err.message }); // Send detailed error response
      }

      console.log("Ticket created:", results);

      // Emit the newly created ticket data to all connected clients
      const ticketData = {
        date_of_ticket,
        airline,
        time,
        arrivalTime,
        luggage_capacity,
        meal,
        fare,
        fromLocation,
        toLocation,
        bookedByUsername,
        flightNumber,
        paymentStatus,
        tripType,
        returnDate,
        returnTime,
        pnr,
        id: results.insertId,
      };
      io.emit("ticketCreated", ticketData);

      res.json({ message: "Ticket created successfully!", ticketData });
    }
  );
});

// Define a new endpoint for displaying a specific ticket by ID
app.get("/tickets/:ticketId", (req, res) => {
  const ticketId = req.params.ticketId; // Extract ticketId from URL parameters
  const username = getUsername();
  console.log("Username:", username);

  // Construct the SQL query to select the ticket by its ID
  const query = "SELECT * FROM tickets WHERE id = ?";

  // Execute the query to fetch the ticket by its ID
  connection.query(query, [ticketId], (err, results) => {
    if (err) {
      console.error("Error fetching ticket:", err);
      res.status(500).json({ error: "Internal Server Error" });
    } else {
      if (results.length === 0) {
        // If no ticket is found with the provided ID, return a 404 error
        res.status(404).json({ error: "Ticket not found" });
      } else {
        // Return the ticket details if found
        res.json(results[0]);
      }
    }
  });
});
app.post("/ticketsedit/:ticketId", (req, res) => {
  const ticketId = req.params.ticketId; // Extract ticketId from URL parameters
  console.log("ticket : ", ticketId);
  // Extract ticket details from request body
  const {
    date_of_ticket,
    deptTime,
    luggage_capacity,
    meal,
    fare,
    from_location,
    to_location,
    no_of_tickets,
    flight_number,
    payment_status,
    trip_type,
    arrivalTime,
    airline,
    pnr,
  } = req.body;

  const query = `UPDATE tickets SET 
    date_of_ticket = ?,
    deptTime = ?,
    luggage_capacity = ?,
    meal = ?,
    fare = ?,
    from_location = ?,
    to_location = ?,
    no_of_tickets = ?,
    flight_number = ?,
    payment_status = ?,
    trip_type = ?,
    arrivalTime = ?,
    airline = ?,
    pnr = ?
  WHERE id = ?`;

  // Execute the query to update the ticket
  connection.query(
    query,
    [
      date_of_ticket,
      deptTime,
      luggage_capacity,
      meal,
      fare,
      from_location,
      to_location,
      no_of_tickets,
      flight_number,
      payment_status,
      trip_type,
      arrivalTime,
      airline,
      pnr,
      ticketId,
    ],
    (err, results) => {
      if (err) {
        console.error("Error updating ticket:", err);
        res.status(500).json({ error: "Internal Server Error" });
      } else {
        // Check if any rows were affected (ticket with provided ID exists)
        if (results.affectedRows === 0) {
          res.status(404).json({ error: "Ticket not found" });
        } else {
          // Fetch and print the updated data from the database
          connection.query(
            `SELECT * FROM tickets WHERE id = ?`,
            [ticketId],
            (err, rows) => {
              if (err) {
                console.error("Error fetching updated ticket data:", err);
              } else {
                console.log("Updated Ticket Data:", rows[0]);
              }
            }
          );
          res.json({ message: "Ticket updated successfully" });
        }
      }
    }
  );
});

//myBooking edit Passenger zaruri functions
app.get("/api/getPassenger/:passengerId", (req, res) => {
  const passengerId = req.params.passengerId;
  const query = "SELECT * FROM passengers WHERE id = ?";
  connection.query(query, [passengerId], (err, result) => {
    if (err) throw err;
    res.json(result[0]);
  });
});

app.post("/api/editPassenger/:passengerId", (req, res) => {
  const passengerId = req.params.passengerId;
  const { surname, given_name, title, passport_number, dob, doe } = req.body;
  const query = `
        UPDATE passengers 
        SET surname = ?, given_name = ?, title = ?, passport_number = ?, dob = ?, doe = ? 
        WHERE id = ?`;
  connection.query(
    query,
    [surname, given_name, title, passport_number, dob, doe, passengerId],
    (err, result) => {
      if (err) throw err;
      res.json({ success: true });
    }
  );
});

app.get("/api/getPassengerDetails", (req, res) => {
  const passengerId = req.query.passenger_id;

  const sql = `
    SELECT 
        p.id as passenger_id,
        p.surname,
        p.given_name,
        p.passport_number,
        p.pnr as passenger_pnr,
        t.date_of_ticket,
        t.deptTime,
        t.luggage_capacity,
        t.meal,
        t.from_location,
        t.to_location,
        t.flight_number,
        t.arrivalTime,
        t.airline,
        u.first_name as agent_first_name,
        u.last_name as agent_last_name,
        u.phone_no as agent_phone
    FROM 
        passengers p
    JOIN 
        tickets t ON p.ticket_id = t.id
    JOIN 
        user u ON p.user_id = u.id
    WHERE 
        p.id = ?
  `;

  connection.query(sql, [passengerId], (err, result) => {
    if (err) throw err;

    if (result.length === 0) {
      return res.status(404).send("Passenger not found");
    }

    const passenger = result[0];
    res.json(passenger);
  });
});

app.get("/print-ticket", async (req, res) => {
  const passengerId = req.query.passenger_id;

  // Your Puppeteer code to generate and print the ticket
  try {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const content = fs.readFileSync(
      path.join(__dirname, "printingTicket.html"),
      "utf8"
    );

    await page.setContent(content);
    await page.emulateMediaType("screen");
    const pdfBuffer = await page.pdf({
      format: "A4",
      printBackground: true,
      margin: {
        top: "20px",
        right: "20px",
        bottom: "20px",
        left: "20px",
      },
    });

    await browser.close();

    // Send the PDF buffer as response
    res.contentType("application/pdf");
    res.send(pdfBuffer);
  } catch (error) {
    console.error("Error generating PDF:", error);
    res.status(500).send("Error generating PDF");
  }
});
app.get("/api/username", (req, res) => {
  const userId = req.query.userId;
  if (!userId) {
    return res.status(400).send("User ID is required");
  }

  const query = "SELECT username FROM user WHERE id = ?";
  connection.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).send("Database query failed");
    }
    if (results.length === 0) {
      return res.status(404).send("User not found");
    }
    res.json({ username: results[0].username });
  });
});
app.get("/ledger", (req, res) => {
  const { startDate, endDate } = req.query;

  if (!startDate || !endDate) {
    return res
      .status(400)
      .json({ error: "Start date and end date are required" });
  }

  const query = `
        SELECT
            tickets.deptTime AS time,
            tickets.date_of_ticket AS Dated, 
            tickets.airline AS Airline, 
            CONCAT(tickets.from_location, ' TO ', tickets.to_location) AS Sector,
            tickets.pnr AS PNR, 
            tickets.date_of_ticket AS Travel_Date, 
            passengers.title AS Type,
            CONCAT(passengers.surname, ' ', passengers.given_name) AS Passenger, 
            tickets.fare AS Amount
        FROM 
            tickets 
        JOIN 
            passengers 
        ON 
            tickets.id = passengers.ticket_id 
        WHERE 
            tickets.date_of_ticket BETWEEN ? AND ?
    `;

  connection.query(query, [startDate, endDate], (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).json({ error: "Server Error" });
      return;
    }

    res.json(results);
  });
});
app.get("/Clientledger", requireLogin, (req, res) => {
  const { startDate, endDate, userId } = req.query;

  if (!startDate || !endDate || !userId) {
    return res
      .status(400)
      .json({ error: "Start date, end date, and user ID are required" });
  }

  const query = `
    SELECT
      tickets.deptTime AS time,
      tickets.date_of_ticket AS Dated,
      tickets.airline AS Airline,
      CONCAT(tickets.from_location, ' TO ', tickets.to_location) AS Sector,
      tickets.pnr AS PNR,
      tickets.date_of_ticket AS Travel_Date,
      passengers.title AS Type,
      CONCAT(passengers.surname, ' ', passengers.given_name) AS Passenger,
      tickets.fare AS Amount
    FROM
      tickets
    JOIN
      passengers ON tickets.id = passengers.ticket_id
    WHERE
      tickets.date_of_ticket BETWEEN ? AND ?
      AND passengers.user_id = ?
    LIMIT 0, 1000;
  `;

  connection.query(query, [startDate, endDate, userId], (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      res.status(500).json({ error: "Server Error" });
      return;
    }

    res.json(results);
  });
});

// Define a route for deleting a ticket
app.delete("/api/deleteTicket", (req, res) => {
  const ticketId = req.query.ticketId;
  // Perform the necessary database query to update the ticket status to "canceled"
  connection.query(
    'UPDATE tickets SET ticket_status = "canceled" WHERE id = ?',
    [ticketId],
    (error, results) => {
      if (error) {
        console.error("Error canceling ticket:", error);
        res.status(500).send("Error canceling ticket");
      } else {
        console.log("Ticket canceled successfully");
        res.sendStatus(200);
      }
    }
  );
});

// Start the server
server.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
