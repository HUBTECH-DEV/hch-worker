import { createServer as createHttpServer } from "node:http";
import { createServer as createTcpServer } from "node:net";

const sockets = new Set();

const httpServer = createHttpServer((request, response) => {
  if (request.url === "/echo") {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        method: request.method,
        body,
        contentType: request.headers["content-type"] ?? null,
      }));
    });
    return;
  }
  if (request.url === "/stalled-body") {
    response.writeHead(200, {
      "content-type": "application/json",
      "content-length": "128",
    });
    response.write('{"partial":');
    return;
  }
  // Intentionally leave the request without response headers. This emulates
  // a peer which accepted TCP but stopped making application-level progress.
});
httpServer.on("connection", (socket) => {
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
});

const tlsBlackhole = createTcpServer((socket) => {
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
  // Accept TCP and never answer the TLS ClientHello.
});

await Promise.all([
  new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve)),
  new Promise((resolve) => tlsBlackhole.listen(0, "127.0.0.1", resolve)),
]);

process.stdout.write(`${JSON.stringify({
  httpPort: httpServer.address().port,
  tlsPort: tlsBlackhole.address().port,
})}\n`);

async function shutdown() {
  for (const socket of sockets) socket.destroy();
  await Promise.allSettled([
    new Promise((resolve) => httpServer.close(resolve)),
    new Promise((resolve) => tlsBlackhole.close(resolve)),
  ]);
  process.exit(0);
}

process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
