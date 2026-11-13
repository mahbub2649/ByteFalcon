CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pthread
SRCS      = $(wildcard src/*.cpp)
OBJS      = $(SRCS:src/%.cpp=build/%.o)

diskscan: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

# The UI is compiled into the binary as a raw string literal: one self-contained file to ship.
build/ui_html.inc: ui/index.html
	@mkdir -p build
	{ printf 'R"__UI__('; cat $<; printf ')__UI__"'; } > $@

build/main.o: build/ui_html.inc
build/%.o: src/%.cpp $(wildcard src/*.hpp)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -Ibuild -c -o $@ $<

install: diskscan
	install -Dm755 diskscan $(HOME)/.local/bin/diskscan

clean:
	rm -rf build diskscan

.PHONY: install clean
