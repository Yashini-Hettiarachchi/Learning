const express = require('express');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Serve all files in repository root as static
app.use(express.static(path.join(__dirname)));

// Fallback to index.html for SPA-style routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
