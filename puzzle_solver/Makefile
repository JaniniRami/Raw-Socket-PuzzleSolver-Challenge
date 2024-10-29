CXX = g++

CXXFLAGS = -Iinclude -std=c++11 

TARGET = puzzlesolver

OBJS = main/main.o \
       src/assign_ports.o \
       src/secret.o  \
	   src/evil_port.o \
	   src/checksum.o \
	   src/expstn.o \
	   src/bonus.o


$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

main/main.o: main/main.cpp
	$(CXX) $(CXXFLAGS) -c main/main.cpp -o main/main.o

src/assign_ports.o: src/assign_ports.cpp
	$(CXX) $(CXXFLAGS) -c src/assign_ports.cpp -o src/assign_ports.o

src/secret.o: src/secret.cpp include/secret.h  
	$(CXX) $(CXXFLAGS) -c src/secret.cpp -o src/secret.o

src/evil_port.o: src/evil_port.cpp include/evil_port.h  
	$(CXX) $(CXXFLAGS) -c src/evil_port.cpp -o src/evil_port.o

src/checksum.o: src/checksum.cpp include/checksum.h  
	$(CXX) $(CXXFLAGS) -c src/checksum.cpp -o src/checksum.o

src/expstn.o: src/expstn.cpp include/expstn.h  
	$(CXX) $(CXXFLAGS) -c src/expstn.cpp -o src/expstn.o

src/bonus.o: src/bonus.cpp include/bonus.h  
	$(CXX) $(CXXFLAGS) -c src/bonus.cpp -o src/bonus.o


# Clean the compiled files
clean:
	rm -f $(TARGET) main/*.o src/*.o
