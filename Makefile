CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wpedantic
LDFLAGS  := -lpcap -lpthread

TARGET   := defender
SRCS     := defender.cpp
HDRS     := arp_guard.hpp dns_guard.hpp

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(LDFLAGS)
	@echo "Build successful: ./$(TARGET)"

clean:
	rm -f $(TARGET) defender.log

# Install as a systemd service (optional)
install: $(TARGET)
	@echo "Copying binary to /usr/local/sbin/..."
	install -m 755 $(TARGET) /usr/local/sbin/$(TARGET)
	@echo "Installing systemd unit..."
	install -m 644 defender.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Run: systemctl enable --now defender"
