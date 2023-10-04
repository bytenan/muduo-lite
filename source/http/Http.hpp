#include <fstream>
#include <sstream>
#include <regex>
#include <cctype>
#include <sys/stat.h>
#include "../Server.hpp"

class Util {
public:
    // 分割字符串
    static size_t Split(const std::string &src, const std::string &sep, std::vector<std::string> *array) {
        size_t offset = 0;
        while (offset < src.size()) {
            size_t pos = src.find(sep, offset);
            if (pos == std::string::npos) {
                array->push_back(src.substr(offset));
                return array->size();
            }
            if (pos == offset) {
                offset = pos + sep.size();
                continue;
            }
            array->push_back(src.substr(offset, pos - offset));
            offset = pos + sep.size();
        }
        return array->size();
    }
    // 读取文件中的所有内容 
    static bool ReadFile(const std::string &filename, std::string *out) {
        std::ifstream is(filename, std::ios::binary);
        if (!is) {
            ERR_LOG("OPEN FILE %s FAILED!!", filename.c_str());
            return false;
        }
        is.seekg(0, is.end);
        size_t size = is.tellg();
        is.seekg(0, is.beg);
        out->clear();
        out->resize(size);
        is.read(&(*out)[0], size);
        if (!is.good()) {
            ERR_LOG("READ FILE %s FAILED!!", filename.c_str());
            is.close();
            return false;
        }
        is.close();
        return true;
    }
    // 往文件中写入内容
    static bool WriteFile(const std::string &filename, const std::string &in) {
        std::ofstream os(filename, std::ios::binary | std::ios::trunc);
        if (!os) {
            ERR_LOG("OPEN FILE %s FAILED!!", filename.c_str());
            return false;
        }
        os.write(in.c_str(), in.size());
        if (!os.good()) {
            ERR_LOG("WRITE FILE %s FAILED!!", filename.c_str());
            os.close();
            return false;
        }
        os.close();
        return true;   
    }
    // RFC3986规定“. - _ ~ 字母 数字”属于不编码字符，其余字符按%HH格式编码
    // W3C规定查询字符串中的空格需要编码为+, 解码则是将+转换为空格
    static std::string UrlEncode(const std::string &url, bool convert_space_to_plus) {
        std::string ans;
        for (auto &c : url) {
            if (c == '.' ||c  == '_' || c == '-' || c == '~' || isalnum(c)) {
                ans += c;
                continue;
            }
            if (c == ' ' && convert_space_to_plus) {
                ans += '+';
                continue;
            }
            char buf[4] = { 0 };
            snprintf(buf, sizeof(buf), "%%%02X", c);
            ans += buf;
        }
        return ans;
    }
    static std::string UrlDecode(const std::string &url, bool convert_plus_to_space) {
        std::string ans;
        for (int i = 0; i < url.size(); ++i) {
            if (url[i] == '+' && convert_plus_to_space) {
                ans += ' ';
                continue;
            }
            if (url[i] == '%' && (i + 2) < url.size()) {
                char v1 = HEXTOI(url[i + 1]);
                char v2 = HEXTOI(url[i + 2]);
                char v = v1 * 16 + v2;
                ans += v;
                i += 2;
                continue;
            }
            ans += url[i];
        }
        return ans;
    }
    // 根据状态码，得到状态信息
    static std::string StatusDescription(int statu) {
        std::unordered_map<int, std::string> dict = {
            {100,  "Continue"},
            {101,  "Switching Protocol"},
            {102,  "Processing"},
            {103,  "Early Hints"},
            {200,  "OK"},
            {201,  "Created"},
            {202,  "Accepted"},
            {203,  "Non-Authoritative Information"},
            {204,  "No Content"},
            {205,  "Reset Content"},
            {206,  "Partial Content"},
            {207,  "Multi-Status"},
            {208,  "Already Reported"},
            {226,  "IM Used"},
            {300,  "Multiple Choice"},
            {301,  "Moved Permanently"},
            {302,  "Found"},
            {303,  "See Other"},
            {304,  "Not Modified"},
            {305,  "Use Proxy"},
            {306,  "unused"},
            {307,  "Temporary Redirect"},
            {308,  "Permanent Redirect"},
            {400,  "Bad Request"},
            {401,  "Unauthorized"},
            {402,  "Payment Required"},
            {403,  "Forbidden"},
            {404,  "Not Found"},
            {405,  "Method Not Allowed"},
            {406,  "Not Acceptable"},
            {407,  "Proxy Authentication Required"},
            {408,  "Request Timeout"},
            {409,  "Conflict"},
            {410,  "Gone"},
            {411,  "Length Required"},
            {412,  "Precondition Failed"},
            {413,  "Payload Too Large"},
            {414,  "URI Too Long"},
            {415,  "Unsupported Media Type"},
            {416,  "Range Not Satisfiable"},
            {417,  "Expectation Failed"},
            {418,  "I'm a teapot"},
            {421,  "Misdirected Request"},
            {422,  "Unprocessable Entity"},
            {423,  "Locked"},
            {424,  "Failed Dependency"},
            {425,  "Too Early"},
            {426,  "Upgrade Required"},
            {428,  "Precondition Required"},
            {429,  "Too Many Requests"},
            {431,  "Request Header Fields Too Large"},
            {451,  "Unavailable For Legal Reasons"},
            {501,  "Not Implemented"},
            {502,  "Bad Gateway"},
            {503,  "Service Unavailable"},
            {504,  "Gateway Timeout"},
            {505,  "HTTP Version Not Supported"},
            {506,  "Variant Also Negotiates"},
            {507,  "Insufficient Storage"},
            {508,  "Loop Detected"},
            {510,  "Not Extended"},
            {511,  "Network Authentication Required"}
        };
        auto it = dict.find(statu);
        if (it == dict.end()) {
            return "Unknow";
        }
        return it->second;
    }
    // 得到文件的后缀
    static std::string ExtendMime(const std::string &filename) {
        std::unordered_map<std::string, std::string> dict = {
            {".aac",        "audio/aac"},
            {".abw",        "application/x-abiword"},
            {".arc",        "application/x-freearc"},
            {".avi",        "video/x-msvideo"},
            {".azw",        "application/vnd.amazon.ebook"},
            {".bin",        "application/octet-stream"},
            {".bmp",        "image/bmp"},
            {".bz",         "application/x-bzip"},
            {".bz2",        "application/x-bzip2"},
            {".csh",        "application/x-csh"},
            {".css",        "text/css"},
            {".csv",        "text/csv"},
            {".doc",        "application/msword"},
            {".docx",       "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
            {".eot",        "application/vnd.ms-fontobject"},
            {".epub",       "application/epub+zip"},
            {".gif",        "image/gif"},
            {".htm",        "text/html"},
            {".html",       "text/html"},
            {".ico",        "image/vnd.microsoft.icon"},
            {".ics",        "text/calendar"},
            {".jar",        "application/java-archive"},
            {".jpeg",       "image/jpeg"},
            {".jpg",        "image/jpeg"},
            {".js",         "text/javascript"},
            {".json",       "application/json"},
            {".jsonld",     "application/ld+json"},
            {".mid",        "audio/midi"},
            {".midi",       "audio/x-midi"},
            {".mjs",        "text/javascript"},
            {".mp3",        "audio/mpeg"},
            {".mpeg",       "video/mpeg"},
            {".mpkg",       "application/vnd.apple.installer+xml"},
            {".odp",        "application/vnd.oasis.opendocument.presentation"},
            {".ods",        "application/vnd.oasis.opendocument.spreadsheet"},
            {".odt",        "application/vnd.oasis.opendocument.text"},
            {".oga",        "audio/ogg"},
            {".ogv",        "video/ogg"},
            {".ogx",        "application/ogg"},
            {".otf",        "font/otf"},
            {".png",        "image/png"},
            {".pdf",        "application/pdf"},
            {".ppt",        "application/vnd.ms-powerpoint"},
            {".pptx",       "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
            {".rar",        "application/x-rar-compressed"},
            {".rtf",        "application/rtf"},
            {".sh",         "application/x-sh"},
            {".svg",        "image/svg+xml"},
            {".swf",        "application/x-shockwave-flash"},
            {".tar",        "application/x-tar"},
            {".tif",        "image/tiff"},
            {".tiff",       "image/tiff"},
            {".ttf",        "font/ttf"},
            {".txt",        "text/plain"},
            {".vsd",        "application/vnd.visio"},
            {".wav",        "audio/wav"},
            {".weba",       "audio/webm"},
            {".webm",       "video/webm"},
            {".webp",       "image/webp"},
            {".woff",       "font/woff"},
            {".woff2",      "font/woff2"},
            {".xhtml",      "application/xhtml+xml"},
            {".xls",        "application/vnd.ms-excel"},
            {".xlsx",       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
            {".xml",        "application/xml"},
            {".xul",        "application/vnd.mozilla.xul+xml"},
            {".zip",        "application/zip"},
            {".3gp",        "video/3gpp"},
            {".3g2",        "video/3gpp2"},
            {".7z",         "application/x-7z-compressed"}
        };
        size_t pos = filename.find_last_of('.');
        if (pos == std::string::npos) {
            return "application/octet-stream";
        }
        auto it = dict.find(filename.substr(pos));
        if (it == dict.end()) {
            return "application/octet-stream";
        }
        return it->second;
    }
    // 判断文件是否是目录文件
    static bool IsDirectoryFile(const std::string &filename) {
        struct stat st;
        int ret = stat(filename.c_str(), &st);
        if (ret < 0) {
            return false;
        }
        return S_ISDIR(st.st_mode);
    }
    // 判断文件是否是普通文件
    static bool IsRegularFile(const std::string &filename) {
        struct stat st;
        int ret = stat(filename.c_str(), &st);
        if (ret < 0) {
            return false;
        }
        return S_ISREG(st.st_mode);
    }
    // 判断路径是否有效(确保用户访问的文件是根目录下的文件)
    static bool IsValidPath(const std::string &path) {
        std::vector<std::string> subdir;
        Split(path, "/", &subdir);
        int level = 0;
        for (auto &dir : subdir) {
            if (dir == "..") {
                if (--level < 0) {
                    return false;
                }
                continue;
            }
            ++level;
        }
        return true;
    }
private:
    // 将16进制数字的其中一位转换成10进制
    static char HEXTOI(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        } else if (c >= 'a' && c <= 'z') {
            return c - 'a' + 10;
        } else if (c >= 'A' && c <= 'Z') {
            return c - 'A' + 10;
        } 
        return -1;
    }
};

class Request {
public:
    // 插入指定头部字段
    void SetHeader(const std::string &key, const std::string &val) {
        headers_.insert(std::make_pair(key, val));
    }
    // 获取指定头部字段
    std::string GetHeader(const std::string &key) {
        auto it = headers_.find(key);
        if (it == headers_.end()) {
            return "";
        }
        return it->second;
    }
    // 判断指定头部字段是否存在
    bool HasHeader(const std::string &key) {
        return headers_.find(key) != headers_.end();
    }
    // 插入指定查询字符串
    void SetParam(const std::string &key, const std::string &val) {
        params_.insert(std::make_pair(key, val));
    }
    // 获取指定查询字符串
    std::string GetParam(const std::string &key) {
        auto it = params_.find(key);
        if (it == params_.end()) {
            return "";
        }
        return it->second;
    }
    // 判断指定查询字符串是否存在
    bool HasParam(const std::string &key) {
        return params_.find(key) != params_.end();
    }
    // 获取正文长度
    size_t GetContentLength() {
        if(!HasHeader("Content-Length")) {
            return 0;
        }
        return std::stol(GetHeader("Content-Length"));
    }
    // 判断是否是短链接
    bool IsClose() {
        if(HasHeader("Connection") && GetHeader("Connection") == "keep-alive") {
            return true;
        }
        return false;
    }
    // 重置Request实例
    void ReSet() {
        method_.clear();
        path_.clear();
        version_.clear();
        body_.clear();
        std::smatch matches;
        matches.swap(matches_);
        headers_.clear();
        params_.clear();
    }

public:
    std::string method_;  //请求方法
    std::string path_;    //资源路径
    std::string version_; //协议版本
    std::string body_;    //请求正文
    std::smatch matches_; //资源路径的正则提取数据
    std::unordered_map<std::string, std::string> headers_; //头部字段
    std::unordered_map<std::string, std::string> params_;  //查询字符串
};

class Response {
public:
    Response() : redirect_flag_(false), status_(200) {}
    Response(int status) : redirect_flag_(false), status_(status) {}
    // 插入指定头部字段
    void SetHeader(const std::string &key, const std::string &val) {
        headers_.insert(std::make_pair(key, val));
    }
    // 获取指定头部字段
    std::string GetHeader(const std::string &key) {
        auto it = headers_.find(key);
        if (it == headers_.end()) {
            return "";
        }
        return it->second;
    }
    // 判断指定头部字段是否存在
    bool HasHeader(const std::string &key) {
        return headers_.find(key) != headers_.end();
    }
    void SetContent(const std::string &body, const std::string &type = "text/html") {
        body_ = body;
        SetHeader("Content-type", type);
    }
    void SetRedirect(const std::string &url, int status = 302) {
        status_ = status;
        redirect_flag_ = true;
        redirect_location_ = url;
    }
    bool IsClose() {
        if(HasHeader("Connection") && GetHeader("Connection") == "keep-alive") {
            return true;
        }
        return false;
    }
    void ReSet() {
        status_ = 200;
        body_.clear();
        headers_.clear();
        redirect_flag_ = false;
        redirect_location_.clear();
    }
public:
    int status_; // 状态码
    std::string body_;   // 响应正文
    std::unordered_map<std::string, std::string> headers_; //头部字段
    bool redirect_flag_; // 是否重定向标志
    std::string redirect_location_; // 重定向位置
};

typedef enum {
    RECV_HTTP_ERROR,
    RECV_HTTP_LINE,
    RECV_HTTP_HEAD,
    RECV_HTTP_BODY,
    RECV_HTTP_OVER
}RecvStatus;

#define MAX_LINE 8096
class Context {
public:
    Context() : resp_status_(200), recv_status_(RECV_HTTP_LINE) {}
    void RecvRequest(Buffer *buf) {
        switch(recv_status_) {
            case RECV_HTTP_LINE: RecvHttpLine(buf);
            case RECV_HTTP_HEAD: RecvHttpHead(buf);
            case RECV_HTTP_BODY: RecvHttpBody(buf);
        }
    }
    int GetRespStatus() {
        return resp_status_;
    }
    RecvStatus GetRecvStatus() {
        return recv_status_;
    }
    Request &GetRequest() {
        return request_;
    }
    void ReSet() {
        resp_status_ = 200;
        recv_status_ = RECV_HTTP_LINE;
        request_.ReSet();
    }
private:
    bool RecvHttpLine(Buffer *buf) {
        if (recv_status_ != RECV_HTTP_LINE) {
            return false;
        }
        std::string line = buf->GetLineAndPushOffSet();
        if (line.size() == 0) {
            if (buf->ReadableSize() > MAX_LINE) {
                resp_status_ = 414; // URI Too Long
                recv_status_ = RECV_HTTP_ERROR;
                return false;
            }
            return true;
        }
        if (line.size() > MAX_LINE) {
            resp_status_ = 414; // URI Too Long
            recv_status_ = RECV_HTTP_ERROR;
            return false;
        }
        if(!ParseHttpLine(line)) {
            return false;
        }
        recv_status_ = RECV_HTTP_HEAD;
        return true;
    }
    bool ParseHttpLine(const std::string &line) {
        std::smatch matches;
        // 最后一个参数的作用是：使匹配时忽略大小写
        std::regex e("(GET|HEAD|POST|PUT|DELETE) ([^?]*)(?:\\?(.*))? (HTTP/1\\.[01])(?:\n|\r\n)?", std::regex::icase);
        bool ret = std::regex_match(line, matches, e);
        if (!ret) {
            resp_status_ = 400;
            recv_status_ = RECV_HTTP_ERROR;
            return false;
        }
        request_.method_ = matches[1];
        // 将method_转换成大写
        std::transform(request_.method_.begin(), request_.method_.end(), request_.method_.begin(), ::toupper);
        request_.path_ = Util::UrlDecode(matches[2], false);
        request_.version_ = matches[4];
        std::string query_string = matches[3];
        std::vector<std::string> query_string_array;
        Util::Split(query_string, "&", &query_string_array);           
        for (auto &str : query_string_array) {
            std::vector<std::string> query_param_array;
            if (Util::Split(str, "=", &query_param_array) != 2) {
                resp_status_ = 400;
                recv_status_ = RECV_HTTP_ERROR;
                return false;
            }
            std::string key = Util::UrlDecode(query_param_array[0], true);
            std::string val = Util::UrlDecode(query_param_array[1], true);
            request_.SetParam(key, val);
        }
        return true;
    }
    bool RecvHttpHead(Buffer *buf) {
        if (recv_status_ != RECV_HTTP_HEAD) {
            return false;
        }   
        while (true) {
            std::string line = buf->GetLineAndPushOffSet();
            if (line.size() == 0) {
                if (buf->ReadableSize() > MAX_LINE) {
                    resp_status_ = 414; // URI Too Long
                    recv_status_ = RECV_HTTP_ERROR;
                    return false;
                }
                return true;
            }
            if (line.size() > MAX_LINE) {
                resp_status_ = 414; // URI Too Long
                recv_status_ = RECV_HTTP_ERROR;
                return false;
            }
            if (line == "\n" || line == "\r\n") {
                break;
            }
            if (!ParseHttpHead(line)) {
                return false;
            }
        }
        recv_status_ = RECV_HTTP_BODY;
        return true;
    }
    bool ParseHttpHead(std::string &line) {
        if (line.back() == '\n') {
            line.pop_back();
        }
        if (line.back() == '\r') {
            line.pop_back();
        }
        std::vector<std::string> array;
        if(Util::Split(line, ": ", &array) != 2) {
            resp_status_ = 400;
            recv_status_ = RECV_HTTP_ERROR;
            return false;
        }
        request_.SetHeader(array[0], array[1]);
        return true;
    }
    bool RecvHttpBody(Buffer *buf) {
        if (recv_status_ != RECV_HTTP_BODY) {
            return false;
        }
        size_t content_length = request_.GetContentLength();
        if (content_length == 0) {
            recv_status_ = RECV_HTTP_OVER;
            return true;
        }
        size_t received_length = request_.body_.size();
        size_t no_received_length = content_length - received_length;
        if (buf->ReadableSize() >= no_received_length) {
            request_.body_.append(buf->ReaderPosition(), no_received_length);
            buf->MoveReaderOffset(no_received_length);
            recv_status_ = RECV_HTTP_OVER;
            return true;
        }
        request_.body_.append(buf->ReaderPosition(), buf->ReadableSize());
        buf->MoveReaderOffset(buf->ReadableSize());
        return true;
    }
private:
    int resp_status_;    // 响应状态码
    RecvStatus recv_status_; // 当前接受及解析请求信息所处的状态
    Request request_;        // 请求信息
};

#define DEFAULT_TIMEOUT 30
class HttpServer {
public:
    using Handler = std::function<void()>;
    using Handlers = std::unordered_map<std::regex, Handler>;

public:
    HttpServer(int port, int timeout = DEFAULT_TIMEOUT) : server_(port) {
        server_.EnableInactiveRelease(timeout);
        server_.SetConnectCallBack(std::bind(&HttpServer::OnConnect, this, std::placeholders::_1));
        server_.SetMessageCallBack(std::bind(&HttpServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
    }
    void SetThreadLoopSize(int size) {
        server_.SetThreadLoopSize(size);
    }
    void Listen() {
        server_.Run();
    }
    void SetBaseDir(const std::string &path) {
        base_dir_ = path;
    }
    void Get(const std::string &pattern, Handler handler) {
        get_handlers_.insert(std::make_pair(std::regex(pattern), handler));
    }
    void Post(const std::string &pattern, Handler handler) {
        post_handlers_.insert(std::make_pair(std::regex(pattern), handler));
    }
    void Put(const std::string &pattern, Handler handler) {
        put_handlers_.insert(std::make_pair(std::regex(pattern), handler));
    }
    void Delete(const std::string &pattern, Handler handler) {
        delete_handlers_.insert(std::make_pair(std::regex(pattern), handler));
    }

private:
    void OnConnect(const ConnectionSharedPtr &conn) {
        conn->SetContent(Context());
        DBG_LOG("NEW CONNECTION: %p", conn.get());
    }
    void OnMessage(const ConnectionSharedPtr &conn, Buffer *buffer) {
        Context *context = conn->Context()->get<Context>();
        context->RecvRequest(buffer);
        Response resp(contex->GetRespStatus());
        if (context->GetRespStatus() >= 400) {
            OnError(&resp);
            WriteResponse(conn, req, resp);
            conn->Shutdown();
            return;
        }
        if (context->GetRecvStatus() != RECV_HTTP_OVER) {
            return;
        }
        Request &req = context->GetRequest();
        Routing(req, &resp);
        WriteResponse(conn, req, resp);
        context->ReSet();
        if (resp.IsClose()) {
            conn->Shutdown();
        }
    }
    void OnError(Response *resp) {
        std::string body;
        body += "<html>";
        body += "<head>";
        body += "<meta charset='utf-8'>"
        body += "</head>";
        body += "<body>";
        body += "<h1>";
        body += std::to_string(resp->status_);
        body += " ";
        body += Util::StatusDescription(resp->status_);
        body += "</h1>";
        body += "</body>";
        body += "</html>";
        resp->SetContent(body, "text/html");
    }
    void WriteResponse(const ConnectionSharedPtr &conn, const Request &req, const Response &resp) {
        if (req.IsClose()) {
            resp.SetHeader("Connection", "close");
        } else {
            resp.SetHeader("Connection", "keep-alive");
        }
        if (!resp.body_.empty()) {
            if (!resp.HasHeader("Content-Length")) {
                resp.SetHeader("Content-Length", std::to_string(resp.body_.size()));
            }
            if (!resp.HasHeader("Content-Type")) {
                resp.SetHeader("Content-Type", "application/octet-stream");
            }
        }
        if (resp.redirect_flag_) {
            resp.SetHeader("Location", resp.redirect_location_);
        }
        std::stringstream resp_str;
        resp_str << req.version_ << " " 
                 << resp.status_ << " " 
                 << Util::StatusDescription(resp.status_) << "\r\n";
        for (auto &head : resp.headers_) {
            resp_str << head->first << " "
                     << head->second << "\r\n";
        }
        resp_str << "\r\n";
        resp_str << resp.body_;
        conn->Send(resp_str.str().c_str(), resp_str.str().size());
    }
    void Dispatcher(const Request &req, const Response &resp, const Handlers &handlers) {
        for (auto &x : handlers) {
            auto &regex = x->first;
            auto &handler = x->second;
            bool ret = std::regex_match(req.path_, req.matches_, regex);
            if (!ret) {
                continue;
            }
            return handler(req, resp);
        }
        resp->status_ = 404;
    }
    void FileHandler(const Request &req, Response *resp) {
        bool ret = Util::ReadFile(req.path_, &resp->body_);
        if (!ret) {
            return;
        }
        resp->SetHeader("Content-Type", Util::ExtendMime(req.path_));
    } 
    bool IsFileRequest(const Request &req) {
        if (base_dir_.empty()) {
            return false;
        }
        if (req.method_ != "GET" && req.method_ != "HEAD") {
            return false;
        }
        if (!Util::IsValidPath(req.path_)) {
            return false;
        }
        std::string path = base_dir_ + req.path_;
        if (req.path_.back() == "/") {
            path += "index.html";
        }
        if (!Util::IsRegularFile(path)) {
            return false;
        }
        req.path_ = path;
        return true;
    }
    void Routing(const Request &req, Response *resp) {
        if (IsFileRequest(req)) {
            return FileHandler(req, resp);
        }
        if (req.method_ == "GET" || req.method_ == "HEAD") {
            return Dispatcher(req, resp, get_handlers_);
        } else if (req.method_ == "POST") {
            return Dispatcher(req, resp, post_handlers_);
        } else if (req.method_ == "PUT") {
            return Dispatcher(req, resp, put_handlers_);
        } else if (req.method_ == "DELETE") {
            return Dispatcher(req, resp, delete_handlers_);
        }
        resp->status_ = 405; // Method Not Allowed 
    }

private:
    Handlers get_handlers_;
    Handlers post_handlers_;
    Handlers put_handlers_;
    Handlers delete_handlers_;
    std::string base_dir_;
    TcpServer server_;
};