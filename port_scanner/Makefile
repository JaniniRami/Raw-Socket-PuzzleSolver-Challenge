# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++11

# Target executable
TARGET = scanner

# Default build target
all: $(TARGET)

# Link the object files to create the executable
$(TARGET): scanner.o
	$(CXX) $(CXXFLAGS) -o $(TARGET) scanner.o

# Compile the C++ source file into object file
scanner.o: scanner.cpp
	$(CXX) $(CXXFLAGS) -c scanner.cpp

# Clean up generated files
clean:
	rm -f *.o $(TARGET)
