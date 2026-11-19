
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
LIBS = -lcrypto++

all: hash

hash: main.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o hash $(LIBS)

clean:
	rm -f hash

.PHONY: all clean

