const http = require('http');
const url = require('url');

// CSRF (Cross-Site Request Forgery) attack demonstration server
// This file showcases vulnerable endpoints that do not properly validate CSRF tokens,
// allowing attackers to perform unauthorized actions on behalf of authenticated users.


const PORT = 7070;

const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    res.setHeader('Content-Type', 'text/html');

    if (pathname === '/') {
        handleHome(res);
    } else if (pathname === '/csrf-safe') {
        handleSafe(res);
    } else {
        res.writeHead(404);
        res.end('Not Found');
    }
});

// handleHome serves a page that demonstrates a CSRF attack.
// It contains a form that submits a POST request to the vulnerable /transfer endpoint.
function handleHome(res) {
    const html = `
        <h1>Welcome to the CSRF Attack server</h1>
        <form action="http://localhost:8080/transfer" method="POST">
            <input type="hidden" name="amount" value="100">
            <input type="submit" value="Claim your rewards!!!">
        </form>
    `;
    res.writeHead(200);
    res.end(html);
}

// handleSafe serves a page that demonstrates a safe endpoint protected against CSRF attacks.
function handleSafe(res) {
    const html = `
        <h1>Welcome to the CSRF Attack server</h1>
        <form action="http://localhost:8080/transfer-safe" method="POST">
            <input type="hidden" name="amount" value="100">
            <input type="submit" value="Claim your rewards!!!">
        </form>
    `;
    res.writeHead(200);
    res.end(html);
}

server.listen(PORT, () => {
    console.log(`CSRF attack server running on :${PORT}`);
});