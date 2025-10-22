const express = require('express');
const { exec } = require('child_process');
const app = express();
const PORT = 3579;

// Middleware to parse JSON requests
app.use(express.json());

// Route to handle the root URL request
app.get('/', (req, res) => {
    res.send('Welcome to the Express server!'); // This is a simple response for the root URL
});

// SECURITY: Endpoint removed due to security vulnerability
// The previous /run-script endpoint allowed command execution which is a major security risk
// If you need this functionality, implement proper authentication and input validation
// 
// app.post('/run-script', (req, res) => {
//     // DANGEROUS: Arbitrary command execution - DO NOT USE
//     exec('neofetch', (error, stdout, stderr) => {
//         if (error) {
//             console.error(`Error executing script: ${error}`);
//             return res.status(500).send(`Error: ${error.message}`);
//         }
//         res.send(`Output: ${stdout}`);
//     });
// });

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://odin.local:${PORT}`);
});
