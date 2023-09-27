.PHONY:all
all:TcpServer TestServer TestClient
TcpServer:TcpServer.cc
	g++ -o $@ $^ -g -std=c++11 -lpthread
TestServer:TestServer.cc 
	g++ -o $@ $^ -g -std=c++11 -lpthread
TestClient:TestClient.cc
	g++ -o $@ $^ -std=c++11
.PHONY:clean
clean:
	rm -f TcpServer TestServer TestClient
