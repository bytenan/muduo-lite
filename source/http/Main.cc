#include "Http.hpp"

#define WWWROOT "./wwwroot/"

std::string RequestToStr(const Request &req) {
    std::stringstream ss;
    ss << req.method_ << " " << req.path_ << " " << req.version_ << "\r\n";
    for (auto &it : req.params_) {
        ss << it.first << ": " << it.second << "\r\n";
    }
    for (auto &it : req.headers_) {
        ss << it.first << ": " << it.second << "\r\n";
    }
    ss << "\r\n";
    ss << req.body_;
    return ss.str(); 
}

void Hello(const Request &req, Response *resp) {
    resp->SetContent(RequestToStr(req), "text/plain");
}

void Login(const Request &req, Response *resp) {
    resp->SetContent(RequestToStr(req), "text/plain");
}

void PutFile(const Request &req, Response *resp) {
    resp->SetContent(RequestToStr(req), "text/plain");
}

void DeleteFile(const Request &req, Response *resp) {
    resp->SetContent(RequestToStr(req), "text/plain");
}

int main() {

    HttpServer server(8888);
    server.SetThreadLoopSize(3);
    server.SetBaseDir(WWWROOT);
    server.Get("/hello", Hello);
    server.Post("/login", Login);
    server.Put("/1234.txt", PutFile);
    server.Delete("/1234.txt", DeleteFile);
    server.Listen();

    return 0;
}
