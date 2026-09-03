// Copyright (c) 2024, PBC Chain
// pbc-webui: Minimal HTTP server + JSON-RPC reverse proxy
// Serves web/pbc-webui.html and proxies /json_rpc to pbc-wallet-rpc
//
// Default: binds 0.0.0.0:8880 (LAN accessible)
// Usage:  pbc-webui [--port 8880] [--rpc-host 127.0.0.1] [--rpc-port 18083]
//                   [--web-dir ./web] [--localhost-only]

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <thread>
#include <csignal>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cerrno>

static volatile bool g_running = true;
static int g_server_fd = -1;  // for clean shutdown

static void signal_handler(int) {
  g_running = false;
  // Close server socket to unblock accept()
  if (g_server_fd >= 0) { close(g_server_fd); g_server_fd = -1; }
}

// ─── Configuration ───────────────────────────────────────────────

struct config {
  std::string bind_ip    = "0.0.0.0";
  uint16_t    port       = 8880;
  std::string rpc_host   = "127.0.0.1";
  uint16_t    rpc_port   = 18083;   // wallet-rpc
  uint16_t    daemon_port = 18831;  // daemon rpc
  std::string web_dir    = "";  // auto-detect
  std::string wallet_log = "";  // path to wallet-rpc log file
};

// ─── Utility ─────────────────────────────────────────────────────

static std::string read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f.is_open()) return "";
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// Read log lines from a file. Supports:
//   ?lines=N       — last N lines from end (default, max 500)
//   ?offset=N      — all lines from byte offset N (for incremental tailing)
// Always returns file_size so client can track position.
static std::string read_tail_json(const std::string& path, int max_lines = 30, long offset = -1) {
  if (path.empty()) return "{\"error\":\"no wallet-log configured\",\"lines\":[],\"file_size\":0}";

  FILE* fp = fopen(path.c_str(), "r");
  if (!fp) return "{\"error\":\"cannot open log file\",\"lines\":[],\"file_size\":0}";

  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  if (fsize <= 0) { fclose(fp); return "{\"lines\":[],\"file_size\":0}"; }

  long read_start;
  long read_size;

  if (offset >= 0 && offset < fsize) {
    // Offset mode: read everything from offset to end
    read_start = offset;
    read_size = fsize - offset;
    // Cap at 512KB to avoid huge reads
    if (read_size > 512 * 1024) {
      read_start = fsize - 512 * 1024;
      read_size = 512 * 1024;
    }
  } else {
    // Tail mode: read last N lines (up to 64KB)
    read_size = std::min(fsize, (long)(64 * 1024));
    read_start = fsize - read_size;
  }

  fseek(fp, read_start, SEEK_SET);
  std::vector<char> buf(read_size);
  size_t got = fread(buf.data(), 1, read_size, fp);
  fclose(fp);

  // Split into lines
  std::vector<std::string> lines;
  std::string current;
  for (size_t i = 0; i < got; i++) {
    if (buf[i] == '\n') {
      if (!current.empty()) lines.push_back(current);
      current.clear();
    } else {
      current += buf[i];
    }
  }
  if (!current.empty()) lines.push_back(current);

  // In tail mode, keep only last max_lines
  int start_idx = 0;
  if (offset < 0) {
    start_idx = (int)lines.size() - max_lines;
    if (start_idx < 0) start_idx = 0;
  }

  // Build JSON array, escaping special chars
  std::string json = "{\"lines\":[";
  bool first = true;
  for (int i = start_idx; i < (int)lines.size(); i++) {
    if (!first) json += ",";
    first = false;
    json += "\"";
    for (char c : lines[i]) {
      if (c == '"') json += "\\\"";
      else if (c == '\\') json += "\\\\";
      else if (c == '\r') continue;
      else if ((unsigned char)c < 0x20) json += ' ';  // control chars → space
      else json += c;
    }
    json += "\"";
  }
  json += "],\"file_size\":";
  json += std::to_string(fsize);
  json += "}";
  return json;
}

static std::string http_response(int code, const std::string& content_type,
                                  const std::string& body) {
  std::ostringstream r;
  r << "HTTP/1.1 " << code << " ";
  switch (code) {
    case 200: r << "OK"; break;
    case 400: r << "Bad Request"; break;
    case 404: r << "Not Found"; break;
    case 502: r << "Bad Gateway"; break;
    default:  r << "Error"; break;
  }
  r << "\r\n"
    << "Content-Type: " << content_type << "\r\n"
    << "Content-Length: " << body.size() << "\r\n"
    << "Access-Control-Allow-Origin: *\r\n"
    << "Access-Control-Allow-Headers: Content-Type\r\n"
    << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
    << "Connection: close\r\n"
    << "\r\n"
    << body;
  return r.str();
}

// ─── RPC Proxy ───────────────────────────────────────────────────

// Send all bytes to socket (handles partial send)
static bool send_all(int fd, const char* data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t n = send(fd, data + sent, len - sent, MSG_NOSIGNAL);
    if (n <= 0) return false;
    sent += n;
  }
  return true;
}

// Read exactly n bytes from socket, returns false on error/timeout
// Handles EINTR (signal interruption) gracefully
static bool recv_exact(int sock, std::string& out, size_t n) {
  out.reserve(out.size() + n);
  size_t got = 0;
  char buf[65536];
  int retries = 0;
  while (got < n) {
    size_t want = std::min(sizeof(buf), n - got);
    ssize_t r = recv(sock, buf, want, 0);
    if (r > 0) {
      out.append(buf, r);
      got += r;
      retries = 0;
    } else if (r == 0) {
      return false;  // peer closed connection
    } else {
      // r < 0: check errno
      if (errno == EINTR) {
        if (++retries > 1000) return false;  // safety valve
        continue;  // retry on signal interruption
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (++retries > 100) return false;
        usleep(10000);  // 10ms backoff
        continue;
      }
      return false;  // real error
    }
  }
  return true;
}

// Read until \r\n\r\n (end of HTTP headers), returns header string
// Leaves nothing in buffer - reads byte by byte only at the boundary
static std::string recv_headers(int sock) {
  std::string hdr;
  hdr.reserve(4096);
  char c;
  while (true) {
    ssize_t r = recv(sock, &c, 1, 0);
    if (r <= 0) break;
    hdr += c;
    if (hdr.size() >= 4 &&
        hdr[hdr.size()-4] == '\r' && hdr[hdr.size()-3] == '\n' &&
        hdr[hdr.size()-2] == '\r' && hdr[hdr.size()-1] == '\n')
      break;
  }
  return hdr;
}

// Read chunked HTTP body properly - waits for each chunk
static std::string recv_chunked(int sock) {
  std::string body;
  body.reserve(512 * 1024);  // 512KB initial

  while (true) {
    // Read chunk size line (hex\r\n)
    std::string size_line;
    char c;
    while (true) {
      ssize_t r = recv(sock, &c, 1, 0);
      if (r <= 0) return body;  // connection closed
      if (c == '\n' && !size_line.empty() && size_line.back() == '\r') {
        size_line.pop_back();  // remove \r
        break;
      }
      size_line += c;
    }

    // Skip empty lines between chunks
    if (size_line.empty()) continue;

    // Parse hex chunk size
    size_t chunk_size = 0;
    try { chunk_size = std::stoull(size_line, nullptr, 16); } catch (...) { break; }
    if (chunk_size == 0) break;  // final chunk "0\r\n"

    // Read exactly chunk_size bytes
    std::string chunk_data;
    if (!recv_exact(sock, chunk_data, chunk_size)) {
      body += chunk_data;  // partial
      break;
    }
    body += chunk_data;

    // Read trailing \r\n after chunk data
    char crlf[2];
    recv(sock, crlf, 2, 0);
  }
  return body;
}

static std::string proxy_json_rpc(const std::string& host, uint16_t port,
                                   const std::string& body) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) return "";

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

  struct timeval tv{};
  tv.tv_sec = 600;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  // Increase receive buffer for large JSON responses (get_transfers can be 5MB+)
  int rcvbuf = 8 * 1024 * 1024;  // 8 MB
  setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

  if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    close(sock);
    return "";
  }

  // Send request
  std::ostringstream req;
  req << "POST /json_rpc HTTP/1.1\r\n"
      << "Host: " << host << ":" << port << "\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "\r\n"
      << body;

  std::string req_str = req.str();
  send_all(sock, req_str.c_str(), req_str.size());

  // Read headers
  std::string headers = recv_headers(sock);
  if (headers.empty()) { close(sock); return ""; }

  // Parse headers for Content-Length or chunked
  std::string h_lower = headers;
  for (auto& c : h_lower) c = tolower(c);

  bool chunked = (h_lower.find("transfer-encoding: chunked") != std::string::npos);

  std::string result;
  if (chunked) {
    result = recv_chunked(sock);
  } else {
    // Use Content-Length as size hint, but always read until EOF
    // This is more robust than recv_exact for large responses
    size_t cl = 0;
    auto cl_pos = h_lower.find("content-length:");
    if (cl_pos != std::string::npos) {
      auto val_start = cl_pos + 15;
      while (val_start < h_lower.size() && h_lower[val_start] == ' ') val_start++;
      try { cl = std::stoull(h_lower.substr(val_start)); } catch (...) {}
    }

    result.reserve(cl > 0 ? cl : 256 * 1024);
    char buf[65536];
    ssize_t n;
    int idle_retries = 0;
    while (true) {
      n = recv(sock, buf, sizeof(buf), 0);
      if (n > 0) {
        result.append(buf, n);
        idle_retries = 0;
        // If we know the size and got it all, stop
        if (cl > 0 && result.size() >= cl) break;
      } else if (n == 0) {
        break;  // peer closed - we have everything
      } else {
        if (errno == EINTR) continue;
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && ++idle_retries < 100) {
          usleep(10000);
          continue;
        }
        break;  // real error or too many retries
      }
    }
  }

  close(sock);
  return result;
}

// Same for non-json_rpc endpoints (e.g. /get_height)
static std::string proxy_raw(const config& cfg, const std::string& path,
                              const std::string& body) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) return "";

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  // PBC FIX (30/08): the raw proxy is meant for DAEMON endpoints (/get_info,
  // /get_transactions per the route comment) — it wrongly connected to the
  // WALLET rpc_port, so /rpc/get_transactions hung forever (wallet has no such
  // endpoint) and froze any UI code awaiting it (bank statement classification).
  addr.sin_port = htons(cfg.daemon_port);
  inet_pton(AF_INET, cfg.rpc_host.c_str(), &addr.sin_addr);

  struct timeval tv{};
  tv.tv_sec = 600;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  int rcvbuf = 8 * 1024 * 1024;
  setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

  if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    close(sock);
    return "";
  }

  std::string method = body.empty() ? "GET" : "POST";
  std::ostringstream req;
  req << method << " " << path << " HTTP/1.1\r\n"
      << "Host: " << cfg.rpc_host << ":" << cfg.rpc_port << "\r\n"
      << "Content-Type: application/json\r\n";
  if (!body.empty())
    req << "Content-Length: " << body.size() << "\r\n";
  req << "\r\n";
  if (!body.empty())
    req << body;

  std::string req_str = req.str();
  send_all(sock, req_str.c_str(), req_str.size());

  // Proper HTTP response reading (same as proxy_json_rpc)
  std::string headers = recv_headers(sock);
  if (headers.empty()) { close(sock); return ""; }

  std::string h_lower = headers;
  for (auto& c : h_lower) c = tolower(c);
  bool chunked = (h_lower.find("transfer-encoding: chunked") != std::string::npos);

  std::string result;
  if (chunked) {
    result = recv_chunked(sock);
  } else {
    size_t cl = 0;
    auto cl_pos = h_lower.find("content-length:");
    if (cl_pos != std::string::npos) {
      auto val_start = cl_pos + 15;
      while (val_start < h_lower.size() && h_lower[val_start] == ' ') val_start++;
      try { cl = std::stoull(h_lower.substr(val_start)); } catch (...) {}
    }
    result.reserve(cl > 0 ? cl : 256 * 1024);
    char buf[65536];
    ssize_t n;
    int idle_retries = 0;
    while (true) {
      n = recv(sock, buf, sizeof(buf), 0);
      if (n > 0) {
        result.append(buf, n);
        idle_retries = 0;
        if (cl > 0 && result.size() >= cl) break;
      } else if (n == 0) {
        break;
      } else {
        if (errno == EINTR) continue;
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && ++idle_retries < 100) {
          usleep(10000);
          continue;
        }
        break;
      }
    }
  }

  close(sock);
  return result;
}

// ─── HTTP Request Parser ─────────────────────────────────────────

struct http_request {
  std::string method;
  std::string path;
  std::string body;
  size_t content_length = 0;
};

static bool parse_request(int client_fd, http_request& req) {
  std::string data;
  char buf[8192];

  // Read headers
  while (true) {
    ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    data.append(buf, n);
    if (data.find("\r\n\r\n") != std::string::npos) break;
    if (data.size() > 65536) return false;
  }

  // Parse first line
  auto first_line_end = data.find("\r\n");
  if (first_line_end == std::string::npos) return false;
  std::string first_line = data.substr(0, first_line_end);

  auto sp1 = first_line.find(' ');
  auto sp2 = first_line.find(' ', sp1 + 1);
  if (sp1 == std::string::npos || sp2 == std::string::npos) return false;

  req.method = first_line.substr(0, sp1);
  req.path   = first_line.substr(sp1 + 1, sp2 - sp1 - 1);

  // Content-Length
  auto cl_pos = data.find("Content-Length:");
  if (cl_pos == std::string::npos) cl_pos = data.find("content-length:");
  if (cl_pos != std::string::npos) {
    auto cl_end = data.find("\r\n", cl_pos);
    std::string cl_str = data.substr(cl_pos + 16, cl_end - cl_pos - 16);
    req.content_length = std::stoul(cl_str);
  }

  // Body
  auto header_end = data.find("\r\n\r\n");
  req.body = data.substr(header_end + 4);

  // Read remaining body if needed
  while (req.body.size() < req.content_length) {
    ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    req.body.append(buf, n);
  }

  return true;
}

// ─── Connection Handler ──────────────────────────────────────────

static void handle_client(int client_fd, const config& cfg) {
  struct timeval tv{};
  tv.tv_sec = 600;  // match proxy timeout (10 min: big dust builds can exceed 2 min)
  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  // Increase send buffer for large JSON responses
  int sndbuf = 2 * 1024 * 1024;  // 2 MB
  setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

  http_request req;
  if (!parse_request(client_fd, req)) {
    close(client_fd);
    return;
  }

  std::string response;

  // CORS preflight
  if (req.method == "OPTIONS") {
    response = http_response(200, "text/plain", "");
  }
  // JSON-RPC proxy → wallet-rpc
  else if (req.path == "/json_rpc" && req.method == "POST") {
    std::string rpc_result = proxy_json_rpc(cfg.rpc_host, cfg.rpc_port, req.body);
    if (rpc_result.empty()) {
      response = http_response(502, "application/json",
        "{\"error\":\"Cannot connect to pbc-wallet-rpc at "
        + cfg.rpc_host + ":" + std::to_string(cfg.rpc_port) + "\"}");
    } else {
      response = http_response(200, "application/json", rpc_result);
    }
  }
  // JSON-RPC proxy → daemon (for economics/blockchain data)
  else if (req.path == "/daemon_rpc" && req.method == "POST") {
    std::string rpc_result = proxy_json_rpc(cfg.rpc_host, cfg.daemon_port, req.body);
    if (rpc_result.empty()) {
      response = http_response(502, "application/json",
        "{\"error\":\"Cannot connect to pbc daemon at "
        + cfg.rpc_host + ":" + std::to_string(cfg.daemon_port) + "\"}");
    } else {
      response = http_response(200, "application/json", rpc_result);
    }
  }
  // Raw RPC proxy (for daemon endpoints like /get_info)
  else if (req.path.find("/rpc/") == 0) {
    std::string real_path = req.path.substr(4);  // strip /rpc prefix
    std::string rpc_result = proxy_raw(cfg, real_path, req.body);
    if (rpc_result.empty()) {
      response = http_response(502, "application/json",
        "{\"error\":\"Cannot connect to RPC\"}");
    } else {
      response = http_response(200, "application/json", rpc_result);
    }
  }
  // Wallet log tail (works even when wallet-rpc is busy)
  else if (req.path == "/wallet-log" || req.path.find("/wallet-log?") == 0) {
    int lines = 30;
    long offset = -1;
    auto qpos = req.path.find("lines=");
    if (qpos != std::string::npos) {
      try { lines = std::stoi(req.path.substr(qpos + 6)); } catch (...) {}
      if (lines < 1) lines = 1;
      if (lines > 500) lines = 500;
    }
    auto opos = req.path.find("offset=");
    if (opos != std::string::npos) {
      try { offset = std::stol(req.path.substr(opos + 7)); } catch (...) {}
    }
    std::string json = read_tail_json(cfg.wallet_log, lines, offset);
    response = http_response(200, "application/json", json);
  }
  // Quick health check — non-blocking connect test to wallet-rpc (1s timeout)
  else if (req.path == "/health") {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    bool wallet_ok = false;
    if (sock >= 0) {
      struct timeval tv{}; tv.tv_sec = 1;
      setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
      setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      struct sockaddr_in a{};
      a.sin_family = AF_INET;
      a.sin_port = htons(cfg.rpc_port);
      inet_pton(AF_INET, cfg.rpc_host.c_str(), &a.sin_addr);
      if (connect(sock, (struct sockaddr*)&a, sizeof(a)) == 0) {
        // Send a tiny RPC and try to read response within 1s
        const char* ping = "POST /json_rpc HTTP/1.1\r\nHost: x\r\nContent-Length: 48\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":\"h\",\"method\":\"get_height\"}";
        if (send(sock, ping, strlen(ping), MSG_NOSIGNAL) > 0) {
          char buf[256];
          ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
          if (r > 0) { buf[r] = 0; wallet_ok = (strstr(buf, "200") != nullptr); }
        }
      }
      close(sock);
    }
    std::string json = wallet_ok
      ? "{\"status\":\"ok\"}"
      : "{\"status\":\"unreachable\"}";
    response = http_response(200, "application/json", json);
  }
  // Serve static files
  else {
    std::string file_path = req.path;
    if (file_path == "/") file_path = "/pbc-webui.html";

    // Security: no path traversal
    if (file_path.find("..") != std::string::npos) {
      response = http_response(400, "text/plain", "Bad Request");
    } else {
      std::string full_path = cfg.web_dir + file_path;
      std::string content = read_file(full_path);
      if (content.empty()) {
        response = http_response(404, "text/plain", "Not Found: " + file_path);
      } else {
        std::string ct = "text/html; charset=utf-8";
        if (file_path.find(".css") != std::string::npos) ct = "text/css";
        else if (file_path.find(".js") != std::string::npos) ct = "application/javascript";
        else if (file_path.find(".png") != std::string::npos) ct = "image/png";
        else if (file_path.find(".svg") != std::string::npos) ct = "image/svg+xml";
        else if (file_path.find(".ico") != std::string::npos) ct = "image/x-icon";
        else if (file_path.find(".json") != std::string::npos) ct = "application/json";
        response = http_response(200, ct, content);
      }
    }
  }

  send_all(client_fd, response.c_str(), response.size());
  close(client_fd);
}

// ─── Auto-detect web/ directory ──────────────────────────────────

static std::string find_web_dir(const char* argv0) {
  // Try relative to executable: ../web/ (if in build/bin/)
  std::string exe_path = argv0;
  auto last_slash = exe_path.rfind('/');

  std::vector<std::string> candidates;
  if (last_slash != std::string::npos) {
    std::string dir = exe_path.substr(0, last_slash);
    candidates.push_back(dir + "/../web");
    candidates.push_back(dir + "/../../web");
    candidates.push_back(dir + "/../../../web");
  }
  candidates.push_back("./web");
  candidates.push_back("../web");

  for (const auto& c : candidates) {
    std::string test = c + "/pbc-webui.html";
    if (access(test.c_str(), R_OK) == 0) return c;
  }
  return "./web";
}

// ─── Main ────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
  config cfg;
  cfg.web_dir = find_web_dir(argv[0]);

  // Parse args
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc)      cfg.port = std::stoi(argv[++i]);
    else if (arg == "--rpc-host" && i + 1 < argc) cfg.rpc_host = argv[++i];
    else if (arg == "--rpc-port" && i + 1 < argc) cfg.rpc_port = std::stoi(argv[++i]);
    else if (arg == "--daemon-port" && i + 1 < argc) cfg.daemon_port = std::stoi(argv[++i]);
    else if (arg == "--web-dir" && i + 1 < argc)  cfg.web_dir = argv[++i];
    else if (arg == "--wallet-log" && i + 1 < argc) cfg.wallet_log = argv[++i];
    else if (arg == "--localhost-only") cfg.bind_ip = "127.0.0.1";
    else if (arg == "--help" || arg == "-h") {
      printf("pbc-webui — PBC Chain Web Dashboard\n\n"
             "Usage: pbc-webui [options]\n\n"
             "Options:\n"
             "  --port <N>           HTTP port (default: 8880)\n"
             "  --rpc-host <IP>      wallet-rpc host (default: 127.0.0.1)\n"
             "  --rpc-port <N>       wallet-rpc port (default: 18083)\n"
             "  --daemon-port <N>    daemon rpc port (default: 18831)\n"
             "  --web-dir <path>     Path to web/ directory\n"
             "  --wallet-log <path>  Path to wallet-rpc log file (for live tailing)\n"
             "  --localhost-only     Bind to 127.0.0.1 only (default: 0.0.0.0)\n"
             "\n"
             "Start pbc-wallet-rpc first, then run this.\n");
      return 0;
    }
  }

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  signal(SIGPIPE, SIG_IGN);

  // Check web dir
  std::string test_file = cfg.web_dir + "/pbc-webui.html";
  if (access(test_file.c_str(), R_OK) != 0) {
    fprintf(stderr, "ERROR: Cannot find %s\n", test_file.c_str());
    fprintf(stderr, "  Use --web-dir to specify the web/ directory\n");
    return 1;
  }

  // Create server socket
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) { perror("socket"); return 1; }

  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg.port);
  inet_pton(AF_INET, cfg.bind_ip.c_str(), &addr.sin_addr);

  if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(server_fd);
    return 1;
  }

  if (listen(server_fd, 32) < 0) {
    perror("listen");
    close(server_fd);
    return 1;
  }

  // Auto-detect wallet log if not specified
  if (cfg.wallet_log.empty()) {
    // Common locations for wallet-rpc log
    const char* home = getenv("HOME");
    if (home) {
      std::vector<std::string> log_candidates = {
        std::string(home) + "/pbc-wallet-rpc.log",
        std::string(home) + "/.pbc/pbc-wallet-rpc.log",
        std::string(home) + "/PBC/pbc-wallet-rpc.log",
        "/var/log/pbc-wallet-rpc.log",
      };
      for (auto& p : log_candidates) {
        if (access(p.c_str(), R_OK) == 0) {
          cfg.wallet_log = p;
          break;
        }
      }
    }
  }

  printf("\n");
  printf("  ╔═══════════════════════════════════════════════╗\n");
  printf("  ║       PBC — Privacy Bank Chain WebUI          ║\n");
  printf("  ╚═══════════════════════════════════════════════╝\n");
  printf("\n");
  printf("  Listening:    http://%s:%d\n", cfg.bind_ip.c_str(), cfg.port);
  printf("  Wallet RPC:   %s:%d\n", cfg.rpc_host.c_str(), cfg.rpc_port);
  printf("  Web dir:      %s\n", cfg.web_dir.c_str());
  printf("  Wallet log:   %s\n", cfg.wallet_log.empty() ? "(not found — use --wallet-log)" : cfg.wallet_log.c_str());
  printf("\n");

  if (cfg.bind_ip == "0.0.0.0") {
    // Show local IP for convenience
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    printf("  LAN access:   http://%s:%d\n", hostname, cfg.port);
    printf("\n");
  }

  printf("  Press Ctrl+C to stop.\n\n");

  g_server_fd = server_fd;  // allow signal handler to close it

  while (g_running) {
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
      break;  // signal handler closed the socket, or error
    }

    // Handle in detached thread
    std::thread([client_fd, &cfg]() {
      handle_client(client_fd, cfg);
    }).detach();
  }

  // Cleanup (signal handler may have already closed it)
  if (g_server_fd >= 0) { close(g_server_fd); g_server_fd = -1; }
  printf("\nShutdown.\n");
  return 0;
}
