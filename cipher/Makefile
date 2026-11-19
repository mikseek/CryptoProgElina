
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
LIBS = -lcrypto++

all: cipher

cipher: main.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o cipher $(LIBS)

clean:
	rm -f cipher

.PHONY: all clean
