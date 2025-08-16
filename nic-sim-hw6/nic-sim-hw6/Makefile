CXX=g++
# Build with extra warnings enabled but silence sign-compare noise
CXXFLAGS=-Wall -Wextra -Wno-sign-compare -std=gnu++11 -include cstdint

SRCS=main.cpp NIC_sim.cpp L2.cpp L3.cpp L4.cpp
OBJS=$(SRCS:.cpp=.o)

all: nic_sim.exe

nic_sim.exe: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f $(OBJS) nic_sim.exe
